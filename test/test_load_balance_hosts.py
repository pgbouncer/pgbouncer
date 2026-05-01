import re

import psycopg
import pytest


async def test_load_balance_hosts_disable_good_first(bouncer):
    with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 2):
        await bouncer.asleep(dbname="hostlist_good_first", duration=0.5, times=2)


async def test_load_balance_hosts_disable_bad_first(bouncer):
    bouncer.admin(f"set server_login_retry=1")
    with bouncer.log_contains(r"closing because: server DNS lookup failed", 1):
        with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 2):
            # Execute two concurrent sleeps to force two backend connections.
            # The first connection will attempt the "bad" host and retry on
            # the "good" host.
            # The second connection will honor `load_balance_hosts` and use the
            # `disable` host.
            await bouncer.asleep(dbname="hostlist_bad_first", duration=0.5, times=2)


def test_load_balance_hosts_reload(bouncer):
    with bouncer.admin_runner.cur() as cur:
        results = cur.execute("show databases").fetchall()
        result = [r for r in results if r[0] == "load_balance_hosts_update"][0]
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
        result = [r for r in results if r[0] == "load_balance_hosts_update"][0]
        assert "round-robin" in result


def test_multi_port(bouncer, pg, pg2):

    config = f"""
    [databases]
    postgres = host={pg.host},{pg2.host} port={pg.port},{pg2.port} load_balance_hosts=round-robin

    [pgbouncer]
    listen_addr = {bouncer.host}
    admin_users = pgbouncer
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    auth_type = trust
    pool_mode = session
    """

    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            port1 = cur.execute("SHOW port").fetchall()[0][0]
            with bouncer.cur(dbname="postgres", user="puser1") as cur:
                port2 = cur.execute("SHOW port").fetchall()[0][0]
    assert port1 != port2
