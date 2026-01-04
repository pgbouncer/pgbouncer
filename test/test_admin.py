import threading
import time

import psycopg
import pytest
from psycopg.rows import dict_row

from .utils import Bouncer, capture, run


def test_reload_error(bouncer):
    """
    Test that admin console correctly raises error during RELOAD
    when invalid value set for auth_type.
    """
    config = f"""
    [databases]
    p1 = host={bouncer.pg.host} port={bouncer.pg.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    admin_users = pgbouncer
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    pool_mode = session
    server_lifetime = {{server_lifetime}}
    """
    good_config = config.format(server_lifetime=0)
    bad_config = config.format(server_lifetime="invalid_server_lifetime")
    with bouncer.run_with_config(good_config):
        with bouncer.ini_path.open("w") as f:
            f.write(bad_config)

        with pytest.raises(
            psycopg.errors.ConfigFileError,
            match=r"RELOAD failed, see logs for additional details",
        ):
            bouncer.admin("RELOAD")


def test_show(bouncer):
    show_items = [
        "clients",
        "config",
        "databases",
        # Calling SHOW FDS on MacOS leaks the returned file descriptors to the
        # python test runner. So we don't test this one directly. SHOW FDS is
        # still tested indirectly by the takeover tests.
        # "fds",
        "help",
        "lists",
        "peers",
        "peer_pools",
        "pools",
        "servers",
        "sockets",
        "active_sockets",
        "state",
        "stats",
        "stats_totals",
        "stats_averages",
        "users",
        "totals",
        "mem",
        "dns_hosts",
        "dns_zones",
    ]

    for item in show_items:
        bouncer.admin(f"SHOW {item}")


def test_socket_id(bouncer) -> None:
    """Test that PgSocket id is assigned as expected for sockets."""
    config = f"""
    [databases]
    p1 = host={bouncer.pg.host} port={bouncer.pg.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    admin_users = pgbouncer
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    pool_mode = session
    server_lifetime = 0
    """

    with bouncer.run_with_config(config):
        with bouncer.cur(
            dbname="pgbouncer", user="pgbouncer", row_factory=dict_row
        ) as admin_cursor:
            admin_cursor.execute("SHOW SOCKETS")
            servers = admin_cursor.fetchall()
            initial_id = max([i["id"] for i in servers])

            for i in range(1, 4):
                conn_2 = bouncer.conn(dbname="p1")
                curr = conn_2.cursor()
                _ = curr.execute("SELECT 1")
                time.sleep(2)
                clients = admin_cursor.execute("SHOW SOCKETS").fetchall()
                assert len(clients) == 3
                assert set(
                    [
                        initial_id,
                        initial_id + i * 2 - 1,
                        initial_id + i * 2,
                    ]
                ) == set([client["id"] for client in clients])
                conn_2.close()
                time.sleep(2)


def test_server_id(bouncer) -> None:
    """Test that PgSocket id is assigned as expected for servers."""
    config = f"""
    [databases]
    p1 = host={bouncer.pg.host} port={bouncer.pg.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    admin_users = pgbouncer
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    server_lifetime = 0
    """

    with bouncer.run_with_config(config):
        with bouncer.cur(
            dbname="pgbouncer", user="pgbouncer", row_factory=dict_row
        ) as admin_cursor:
            admin_cursor.execute("SHOW SOCKETS")
            servers = admin_cursor.fetchall()
            initial_id = max([i["id"] for i in servers])

            for i in range(1, 4):
                conn_2 = bouncer.conn(dbname="p1")
                curr = conn_2.cursor()
                _ = curr.execute("SELECT 1")
                time.sleep(2)
                clients = admin_cursor.execute("SHOW SERVERS").fetchall()
                assert [
                    initial_id + i * 2,
                ] == [client["id"] for client in clients]
                conn_2.close()
                time.sleep(2)


def test_client_id(bouncer) -> None:
    """Test that PgSocket id is assigned as expected for clients."""
    config = f"""
    [databases]
    p1 = host={bouncer.pg.host} port={bouncer.pg.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    admin_users = pgbouncer
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    server_lifetime = 0
    """

    with bouncer.run_with_config(config):
        initial_id = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)[0]["id"]

        for i in range(1, 4):
            clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
            assert [
                initial_id + i,
            ] == [client["id"] for client in clients]


def test_client_states(bouncer):
    conn_1 = bouncer.conn(dbname="p3x", user="clientstate")

    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    client_id = [
        client
        for client in clients
        if client["database"] == "p3x" and client["user"] == "clientstate"
    ][0]["state"]
    assert client_id == "idle"

    cur_1 = conn_1.cursor()

    bouncer.admin("PAUSE p3x")

    # Give a moment for the query to hit the pause
    time.sleep(1)

    # We'll run a query in a separate thread to simulate blocking/waiting
    def run_blocked_query():
        # This query will attempt to run but the DB is paused
        cur_1.execute("SELECT pg_sleep(5)")
        # If the DB is never resumed, this call will block until test times out
        # Once the DB is resumed, it should succeed
        cur_1.fetchone()

    thread = threading.Thread(target=run_blocked_query)
    thread.start()

    # Give the thread a moment to attempt the query
    time.sleep(1)

    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    client_id = [
        client
        for client in clients
        if client["database"] == "p3x" and client["user"] == "clientstate"
    ][0]["state"]
    assert client_id == "waiting"

    bouncer.admin("RESUME p3x")

    # Wait for the thread to finish the blocked query
    thread.join(timeout=10)
    # Confirm the query eventually completes
    assert not thread.is_alive(), "Expected the blocked query thread to finish"

    cur_1.execute("BEGIN; SELECT pg_sleep(5);")

    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    client_id = [
        client
        for client in clients
        if client["database"] == "p3x" and client["user"] == "clientstate"
    ][0]["state"]
    assert client_id == "active"

    # Rollback/commit to end the long-running transaction
    cur_1.execute("ROLLBACK")

    # Cleanup
    cur_1.close()
    conn_1.close()


def test_kill_db(bouncer: "Bouncer"):
    # Connect to client as user A
    conn_1 = bouncer.conn(dbname="p0", user="maxedout")

    # Connect to client as user B
    conn_2 = bouncer.conn(dbname="p0", user="maxedout")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    assert len(clients) == 3

    # Issue kill command
    bouncer.admin("KILL p0")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 1

    conn_1.close()
    conn_2.close()


def test_kill_db_nonexisting(bouncer: "Bouncer"):
    # Connect to client as user A
    conn_1 = bouncer.conn(dbname="p0", user="maxedout")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    assert len(clients) == 2

    # Issue kill command
    with pytest.raises(
        psycopg.errors.ProtocolViolation,
        match=r"no such database: dne",
    ):
        clients = bouncer.admin("KILL dne")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 2

    conn_1.close()


def test_kill_all(bouncer: "Bouncer"):
    # Connect to client as user A to first database
    conn_1 = bouncer.conn(dbname="p0", user="maxedout")

    # Connect to client as user B to second database
    conn_2 = bouncer.conn(dbname="p1", user="maxedout")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    assert len(clients) == 3

    # Issue kill command
    bouncer.admin("KILL")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 1

    conn_1.close()
    conn_2.close()


def test_kill_client_nonexisting(bouncer):
    # Connect to client as user A
    conn_1 = bouncer.conn(dbname="p0", user="maxedout")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    assert len(clients) == 2

    # Issue kill client command
    with pytest.raises(
        psycopg.errors.ProtocolViolation,
        match=r"client not found",
    ):
        clients = bouncer.admin(f"KILL_CLIENT 1000")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 2

    conn_1.close()


def test_kill_client_invalid(bouncer):
    # Connect to client as user A
    conn_1 = bouncer.conn(dbname="p0", user="maxedout")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 2

    # Issue kill client command
    with pytest.raises(
        psycopg.errors.ProtocolViolation,
        match=r"invalid client pointer supplied",
    ):
        clients = bouncer.admin("KILL_CLIENT non_existant_client_id")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 2

    conn_1.close()


def test_kill_client(bouncer):
    # Connect to client as user A
    conn_1 = bouncer.conn(dbname="p0", user="maxedout")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    assert len(clients) == 2

    # Get clients id
    client_id = [client for client in clients if client["database"] == "p0"][0]["id"]

    # Issue kill client command
    clients = bouncer.admin(f"KILL_CLIENT {client_id}")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 1

    conn_1.close()


def test_show_version(bouncer):
    admin_version = bouncer.admin_value(f"SHOW VERSION")
    subprocess_result = capture(
        [*bouncer.base_command(), "--version"],
    )
    subprocess_version = subprocess_result.split("\n")[0]
    assert admin_version == subprocess_version


def test_help(bouncer):
    run([*bouncer.base_command(), "--help"])


def test_show_stats(bouncer):
    # Use session pooling database to see differenecs between transactions and
    # server assignments
    bouncer.default_db = "p3"
    bouncer.test()
    bouncer.test()
    bouncer.test()
    bouncer.test()
    with bouncer.cur() as cur:
        with cur.connection.transaction():
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")
        with cur.connection.transaction():
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")

    stats = bouncer.admin("SHOW STATS", row_factory=dict_row)
    p3_stats = next(s for s in stats if s["database"] == "p3")
    assert p3_stats is not None
    # 5 connection attempts (and thus assignments)
    assert p3_stats["total_server_assignment_count"] == 5
    # 4 autocommit queries + 2 transactions
    assert p3_stats["total_xact_count"] == 6
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK
    assert p3_stats["total_query_count"] == 15

    stats = bouncer.admin("SHOW STATS_TOTALS", row_factory=dict_row)
    p3_stats = next(s for s in stats if s["database"] == "p3")
    assert p3_stats is not None
    # 5 connection attempts (and thus assignments)
    assert p3_stats["server_assignment_count"] == 5
    # 4 autocommit queries + 2 transactions
    assert p3_stats["xact_count"] == 6
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK
    assert p3_stats["query_count"] == 15

    totals = bouncer.admin("SHOW TOTALS")
    # 5 connection attempts (and thus assignments)
    assert ("total_server_assignment_count", 5) in totals
    # 4 autocommit queries + 2 transactions + 4 admin commands
    assert ("total_xact_count", 10) in totals
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK + 4 admin commands
    assert ("total_query_count", 19) in totals
