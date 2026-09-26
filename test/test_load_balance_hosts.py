import asyncio
import re

import psycopg
import pytest
from psycopg.rows import dict_row

from .utils import WINDOWS

HOST_RELOAD_DB = "host_reload"


def host_reload_config(
    bouncer,
    hosts,
    *,
    connect_query=None,
    load_balance_hosts="round-robin",
    pool_mode="session",
    port=None,
    query_timeout=0,
    server_login_retry=15,
):
    database_settings = [
        f"host={hosts}",
        f"port={bouncer.pg.port if port is None else port}",
        "dbname=p0",
        "user=bouncer",
        f"load_balance_hosts={load_balance_hosts}",
    ]
    if connect_query is not None:
        database_settings.append(f"connect_query='{connect_query}'")

    return f"""
    [databases]
    {HOST_RELOAD_DB} = {" ".join(database_settings)}

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    admin_users = pgbouncer
    auth_file = {bouncer.auth_path}
    logfile = {bouncer.log_path}
    pool_mode = {pool_mode}
    query_timeout = {query_timeout}
    server_lifetime = 3600
    server_login_retry = {server_login_retry}
    """


def reload_host_config(bouncer, hosts, **kwargs):
    with bouncer.ini_path.open("w") as config_file:
        config_file.write(host_reload_config(bouncer, hosts, **kwargs))
    bouncer.admin("RELOAD")


def host_reload_servers(bouncer):
    return [
        server
        for server in bouncer.admin("SHOW SERVERS", row_factory=dict_row)
        if server["database"] == HOST_RELOAD_DB
    ]


async def wait_for_host_reload_pool(bouncer, **expected):
    for _ in range(100):
        pools = [
            pool
            for pool in bouncer.admin("SHOW POOLS", row_factory=dict_row)
            if pool["database"] == HOST_RELOAD_DB
        ]
        if pools and all(pools[0][key] == value for key, value in expected.items()):
            return
        await asyncio.sleep(0.05)
    pytest.fail(f"pool did not reach expected state: {expected}")


async def test_load_balance_hosts_disable_good_first(bouncer):
    with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 2):
        await bouncer.asleep(dbname="hostlist_good_first", duration=0.5, times=2)


async def test_load_balance_hosts_disable_bad_first(bouncer):
    bouncer.admin(f"set server_login_retry=1")
    with (
        bouncer.log_contains(r"closing because: server DNS lookup failed", 1),
        bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 2),
    ):
        # Execute two concurrent sleeps to force two backend connections.
        # The first connection will attempt the "bad" host and retry on
        # the "good" host.
        # The second connection will honor `load_balance_hosts` and use the
        # `disable` host.
        await bouncer.asleep(dbname="hostlist_bad_first", duration=0.5, times=2)


async def test_round_robin_preserves_duplicate_host_weighting(bouncer):
    hosts = f"{bouncer.pg.host},{bouncer.pg.host},unresolvable-hostname"

    with bouncer.run_with_config(
        host_reload_config(bouncer, hosts, server_login_retry=1)
    ):
        with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 2):
            with bouncer.log_contains(r"closing because: server DNS lookup failed", 1):
                # Keeping the first two backends busy forces a third attempt.
                # The duplicate healthy entry is a deliberate weight, so the
                # selected sequence must be healthy, healthy, unresolvable.
                await bouncer.asleep(
                    dbname=HOST_RELOAD_DB,
                    duration=0.5,
                    times=3,
                )


def test_load_balance_hosts_reload(bouncer):
    with bouncer.admin_runner.cur() as cur:
        results = cur.execute("show databases").fetchall()
        result = next(r for r in results if r[0] == "load_balance_hosts_update")
        assert "disable" in result

    with bouncer.ini_path.open() as f:
        original = f.read()
    with bouncer.ini_path.open("w") as f:
        f.write(
            re.sub(
                r"^(load_balance_hosts_update.*load_balance_hosts=)disable",
                "\\1round-robin",
                original,
                flags=re.MULTILINE,
            )
        )

    bouncer.admin("reload")

    with bouncer.admin_runner.cur() as cur:
        results = cur.execute("show databases").fetchall()
        result = next(r for r in results if r[0] == "load_balance_hosts_update")
        assert "round-robin" in result


@pytest.mark.parametrize(
    ("old_hosts", "new_hosts", "expected_close_needed"),
    [
        pytest.param("{primary}", "{primary}", 0, id="unchanged"),
        pytest.param(
            "{primary}",
            "{primary},{other}",
            0,
            id="host-added",
        ),
        pytest.param(
            "{primary},{other}",
            "{other},{primary}",
            0,
            id="hosts-reordered",
        ),
        pytest.param(
            "{primary},{other}",
            "{primary},{other},{other}",
            0,
            id="duplicate-weight-changed",
        ),
        pytest.param(
            "{primary},{other}",
            "{primary}",
            0,
            id="unused-host-removed",
        ),
        pytest.param(
            "{primary},{other}",
            "{other}",
            1,
            id="connected-host-removed",
        ),
        pytest.param(
            "{primary}",
            "{other}",
            1,
            id="hosts-replaced",
        ),
    ],
)
def test_host_list_reload_only_dirties_connections_to_removed_hosts(
    bouncer, old_hosts, new_hosts, expected_close_needed
):
    hosts = {
        "primary": bouncer.pg.host,
        # The tests always select the first host for their one backend connection,
        # so this address does not need to accept connections.
        "other": "127.0.0.2",
    }
    old_hosts = old_hosts.format_map(hosts)
    new_hosts = new_hosts.format_map(hosts)

    with bouncer.run_with_config(host_reload_config(bouncer, old_hosts)):
        with bouncer.cur(dbname=HOST_RELOAD_DB) as cur:
            backend_pid = cur.execute("SELECT pg_backend_pid()").fetchone()[0]
            servers_before = host_reload_servers(bouncer)
            assert len(servers_before) == 1
            server_id = servers_before[0]["id"]

            reload_host_config(bouncer, new_hosts)

            servers_after = host_reload_servers(bouncer)
            assert len(servers_after) == 1
            assert servers_after[0]["id"] == server_id
            assert servers_after[0]["close_needed"] == expected_close_needed

            if not expected_close_needed:
                assert (
                    cur.execute("SELECT pg_backend_pid()").fetchone()[0] == backend_pid
                )


def test_load_balance_hosts_change_does_not_dirty_existing_connections(bouncer):
    hosts = f"{bouncer.pg.host},127.0.0.2"
    initial_config = host_reload_config(bouncer, hosts, load_balance_hosts="disable")

    with bouncer.run_with_config(initial_config):
        with bouncer.cur(dbname=HOST_RELOAD_DB) as cur:
            cur.execute("SELECT 1")
            server_id = host_reload_servers(bouncer)[0]["id"]

            reload_host_config(bouncer, hosts, load_balance_hosts="round-robin")

            servers = host_reload_servers(bouncer)
            assert len(servers) == 1
            assert servers[0]["id"] == server_id
            assert servers[0]["close_needed"] == 0


def test_non_host_connection_change_still_dirties_existing_connections(bouncer):
    initial_config = host_reload_config(bouncer, bouncer.pg.host)

    with bouncer.run_with_config(initial_config):
        with bouncer.cur(dbname=HOST_RELOAD_DB) as cur:
            cur.execute("SELECT 1")

            reload_host_config(
                bouncer,
                bouncer.pg.host,
                connect_query="SELECT 1",
            )

            servers = host_reload_servers(bouncer)
            assert len(servers) == 1
            assert servers[0]["close_needed"] == 1


def test_invalid_host_reload_keeps_last_applied_host_state(bouncer):
    initial_config = host_reload_config(bouncer, bouncer.pg.host)

    with bouncer.run_with_config(initial_config):
        with bouncer.cur(dbname=HOST_RELOAD_DB) as cur:
            backend_pid = cur.execute("SELECT pg_backend_pid()").fetchone()[0]
            server_id = host_reload_servers(bouncer)[0]["id"]

            with bouncer.ini_path.open("w") as config_file:
                config_file.write(
                    host_reload_config(
                        bouncer,
                        f"{bouncer.pg.host},127.0.0.2",
                        port="not-a-port",
                    )
                )

            with pytest.raises(psycopg.errors.ConfigFileError):
                bouncer.admin("RELOAD")

            servers = host_reload_servers(bouncer)
            assert len(servers) == 1
            assert servers[0]["id"] == server_id
            assert servers[0]["close_needed"] == 0
            assert cur.execute("SELECT pg_backend_pid()").fetchone()[0] == backend_pid


@pytest.mark.parametrize(
    "invalid_hosts",
    [
        pytest.param(",127.0.0.1", id="leading-empty-entry"),
        pytest.param("127.0.0.1,,127.0.0.2", id="middle-empty-entry"),
        pytest.param("127.0.0.1,", id="trailing-empty-entry"),
    ],
)
def test_empty_host_entry_reload_keeps_last_applied_host_state(bouncer, invalid_hosts):
    initial_config = host_reload_config(bouncer, bouncer.pg.host)

    with bouncer.run_with_config(initial_config):
        with bouncer.cur(dbname=HOST_RELOAD_DB) as cur:
            backend_pid = cur.execute("SELECT pg_backend_pid()").fetchone()[0]
            server_id = host_reload_servers(bouncer)[0]["id"]

            with bouncer.ini_path.open("w") as config_file:
                config_file.write(host_reload_config(bouncer, invalid_hosts))

            with pytest.raises(psycopg.errors.ConfigFileError):
                bouncer.admin("RELOAD")

            servers = host_reload_servers(bouncer)
            assert len(servers) == 1
            assert servers[0]["id"] == server_id
            assert servers[0]["close_needed"] == 0
            assert cur.execute("SELECT pg_backend_pid()").fetchone()[0] == backend_pid


def test_host_membership_change_clears_cached_connect_failure(bouncer):
    bad_host = "unresolvable-hostname"
    initial_config = host_reload_config(
        bouncer,
        bad_host,
        query_timeout=3,
        server_login_retry=10,
    )

    with bouncer.run_with_config(initial_config):
        with bouncer.log_contains(r"closing because: server DNS lookup failed"):
            with pytest.raises(psycopg.OperationalError):
                bouncer.test(dbname=HOST_RELOAD_DB, connect_timeout=5)

        reload_host_config(
            bouncer,
            f"{bad_host},{bouncer.pg.host}",
            query_timeout=3,
            server_login_retry=10,
        )

        # The old failure must not impose its ten-second retry delay on the
        # updated host set. Selection advances past the failed single host.
        bouncer.test(dbname=HOST_RELOAD_DB, connect_timeout=5)


@pytest.mark.parametrize(
    ("reload_kind", "expected_canceled_logins"),
    [
        pytest.param("host-added", 0, id="host-added"),
        pytest.param("connect-query-changed", 1, id="connection-identity-changed"),
    ],
)
@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
async def test_reload_during_login_does_not_trigger_server_login_retry(
    pg, bouncer, reload_kind, expected_canceled_logins
):
    initial_config = host_reload_config(
        bouncer,
        bouncer.pg.host,
        pool_mode="transaction",
        query_timeout=6,
        server_login_retry=10,
    )

    with bouncer.run_with_config(initial_config):
        # Establish the pool's welcome message and leave one reusable backend.
        bouncer.test(dbname=HOST_RELOAD_DB)

        # Keep a client connected before reload so it already has the cached
        # welcome message. Its next query exercises check_fast_fail().
        async with await bouncer.aconn(
            dbname=HOST_RELOAD_DB, connect_timeout=12
        ) as existing_client:
            async with existing_client.cursor() as existing_cursor:
                await existing_cursor.execute("SELECT 1")

                # Keep the established backend busy while a second backend
                # remains in the login phase. The reload either preserves that
                # attempt (host addition) or intentionally cancels it (a full
                # connection-identity change).
                pg.configure("pre_auth_delay to '5s'")
                pg.reload()

                first_query = bouncer.asql(
                    "SELECT pg_sleep(2)",
                    dbname=HOST_RELOAD_DB,
                    connect_timeout=12,
                )
                await wait_for_host_reload_pool(bouncer, sv_active=1)

                second_query = bouncer.asql(
                    "SELECT 1", dbname=HOST_RELOAD_DB, connect_timeout=12
                )
                await wait_for_host_reload_pool(bouncer, sv_active=1, sv_login=1)

                if reload_kind == "host-added":
                    reloaded_hosts = f"{bouncer.pg.host},127.0.0.2"
                    reload_kwargs = {}
                else:
                    reloaded_hosts = bouncer.pg.host
                    reload_kwargs = {"connect_query": "SELECT 1"}

                with bouncer.log_contains(
                    rf"{HOST_RELOAD_DB}.*closing because: connect string changed",
                    times=expected_canceled_logins,
                ):
                    with bouncer.log_contains(
                        r"server login has been failing, cached error: "
                        r"connect string changed \(server_login_retry\)",
                        times=0,
                    ):
                        reload_host_config(
                            bouncer,
                            reloaded_hosts,
                            pool_mode="transaction",
                            query_timeout=6,
                            server_login_retry=10,
                            **reload_kwargs,
                        )

                        await first_query
                        existing_client_query = existing_cursor.execute("SELECT 1")
                        results = await asyncio.gather(
                            second_query,
                            existing_client_query,
                            return_exceptions=True,
                        )

        assert not [result for result in results if isinstance(result, BaseException)]
        assert results[0] == [(1,)]
