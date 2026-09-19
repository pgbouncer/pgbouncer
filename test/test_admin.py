import asyncio
import socket
import struct
import threading
import time

import psycopg
import pytest
from psycopg.rows import dict_row

from .utils import Bouncer, PortLock, capture, run


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


def test_show_user(bouncer):
    """
    Test `SHOW USERS` command.

    Specifically we are trying to fix a bug where pool_size and reserve_pool_size
    would take its value from the previous row if a pool_size was not set for a later
    user. In this case test2's pool_size should not be impacted by test1's value.
    """
    config = f"""
    [databases]
    p1 = host={bouncer.pg.host} port={bouncer.pg.port}

    [pgbouncer]
    auth_file = {bouncer.auth_path}
    auth_type = trust
    auth_user = postgres
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    admin_users = pgbouncer
    pool_mode = session

    [users]
    test1 = pool_size=1 reserve_pool_size=1
    test2 =
    """

    with bouncer.run_with_config(config):
        users = bouncer.admin(f"SHOW USERS", row_factory=dict_row)
        users = [user for user in users if user["name"] in ["test1", "test2"]]
        assert ["1", ""] == [user["pool_size"].lstrip().rstrip() for user in users]
        assert ["1", ""] == [
            user["reserve_pool_size"].lstrip().rstrip() for user in users
        ]


def test_show(bouncer):
    show_items = [
        "clients",
        "config",
        "databases",
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


def test_jdbc_extra_float_digits(bouncer):
    bouncer.admin("SET extra_float_digits = 2")


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

    with (
        bouncer.run_with_config(config),
        bouncer.cur(
            dbname="pgbouncer", user="pgbouncer", row_factory=dict_row
        ) as admin_cursor,
    ):
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
            assert {
                initial_id,
                initial_id + i * 2 - 1,
                initial_id + i * 2,
            } == {client["id"] for client in clients}
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

    with (
        bouncer.run_with_config(config),
        bouncer.cur(
            dbname="pgbouncer", user="pgbouncer", row_factory=dict_row
        ) as admin_cursor,
    ):
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
    client_id = next(
        client
        for client in clients
        if client["database"] == "p3x" and client["user"] == "clientstate"
    )["state"]
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
    client_id = next(
        client
        for client in clients
        if client["database"] == "p3x" and client["user"] == "clientstate"
    )["state"]
    assert client_id == "waiting"

    bouncer.admin("RESUME p3x")

    # Wait for the thread to finish the blocked query
    thread.join(timeout=10)
    # Confirm the query eventually completes
    assert not thread.is_alive(), "Expected the blocked query thread to finish"

    cur_1.execute("BEGIN; SELECT pg_sleep(5);")

    clients = bouncer.admin("SHOW CLIENTS", row_factory=dict_row)
    client_id = next(
        client
        for client in clients
        if client["database"] == "p3x" and client["user"] == "clientstate"
    )["state"]
    assert client_id == "active"

    # Rollback/commit to end the long-running transaction
    cur_1.execute("ROLLBACK")

    # Cleanup
    cur_1.close()
    conn_1.close()


async def await_show_rows(bouncer, command, count, timeout=20, **match):
    """
    Poll an admin SHOW command until `count` of its rows match `match`.

    Returns the matching rows. Unlike utils.wait_until() this yields to the
    event loop, so it can be used to wait for connections opened with atest().
    """
    deadline = time.monotonic() + timeout
    while True:
        rows = [
            row
            for row in bouncer.admin(command, row_factory=dict_row)
            if all(row[column] == value for column, value in match.items())
        ]
        if len(rows) == count:
            return rows
        assert time.monotonic() < deadline, f"{command}: {rows}"
        await asyncio.sleep(0.1)


async def test_maxwait_for_clients_queued_before_their_first_query(bouncer):
    """
    Test that `maxwait` and `wait` count a client that was queued before it
    ever sent a query.

    A client that arrives while its pool has no server connection is parked
    during login, so it never sets query_start. `query_wait_timeout` counts
    such a client down from when it was queued, and `maxwait`/`wait` have to
    report that same wait instead of 0, or a stuck pool looks idle.
    """
    # Nothing has used this pool yet, so it has no welcome message to hand a
    # new client, and while the pooler is paused it will not open a server
    # connection to get one. Clients that arrive now queue up during login.
    bouncer.admin("PAUSE")
    start = time.monotonic()
    # These clients stay queued for as long as this test watches them, which is
    # well past libpq's default connect_timeout of 3s that utils.py sets.
    queued = [bouncer.atest(dbname="p0", connect_timeout=30) for _ in range(2)]

    try:
        await await_show_rows(
            bouncer, "SHOW CLIENTS", 2, database="p0", state="waiting"
        )
        await asyncio.sleep(2)

        [pool] = await await_show_rows(
            bouncer, "SHOW POOLS", 1, database="p0", cl_waiting=2
        )
        clients = await await_show_rows(
            bouncer, "SHOW CLIENTS", 2, database="p0", state="waiting"
        )
        elapsed = time.monotonic() - start

        maxwait = pool["maxwait"] + pool["maxwait_us"] / 1_000_000
        assert 1 <= maxwait <= elapsed + 1

        for client in clients:
            wait = client["wait"] + client["wait_us"] / 1_000_000
            assert 1 <= wait <= elapsed + 1
    finally:
        bouncer.admin("RESUME")
        await asyncio.gather(*queued, return_exceptions=True)


async def test_wait_for_a_queued_cancel_request(bouncer):
    """
    Test that `wait` counts a cancel request that is queued for a connection.

    A cancel request sets neither query_start nor wait_start, so it needs its
    own clock: `cancel_wait_timeout` counts it down from its request_time, and
    `wait` has to report that same wait instead of 0.
    """
    # A cancel request whose key names another peer is queued on that peer's
    # pool until a connection to the peer can be opened. Nothing listens on
    # this port, so the connection keeps failing and the request keeps waiting.
    #
    # The port is taken from PortLock even though nothing will ever bind it:
    # the point is that no other test's fixture may bind it either, because
    # anything answering there would let the cancel request through.
    dead_peer = PortLock()
    bouncer.write_ini(f"peer_id = 1\n[peers]\n2 = host=127.0.0.1 port={dead_peer.port}")
    await bouncer.restart()

    try:
        # So that the request is not disconnected while we are watching it.
        bouncer.admin("set cancel_wait_timeout=0")

        with socket.create_connection((bouncer.host, bouncer.port)) as sock:
            start = time.monotonic()
            # A CancelRequest for peer 2. PgBouncer reads the peer id out of
            # the 2nd and 3rd byte of the 8 byte key, and the forwarding TTL
            # out of the last 2 bits of the 8th, so the key needs no real
            # client behind it to be routed to the peer's pool.
            sock.sendall(struct.pack("!IIII", 16, 80877102, 2 << 16, 0b11))

            await await_show_rows(
                bouncer, "SHOW CLIENTS", 1, state="waiting_cancel_req"
            )
            await asyncio.sleep(2)

            [request] = await await_show_rows(
                bouncer, "SHOW CLIENTS", 1, state="waiting_cancel_req"
            )
            elapsed = time.monotonic() - start

            wait = request["wait"] + request["wait_us"] / 1_000_000
            assert 1 <= wait <= elapsed + 1
    finally:
        dead_peer.release()


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
    client_id = next(client for client in clients if client["database"] == "p0")["id"]

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
    assert p3_stats["total_client_login_count"] == 5
    # 4 autocommit queries + 2 transactions
    assert p3_stats["total_xact_count"] == 6
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK
    assert p3_stats["total_query_count"] == 15

    stats = bouncer.admin("SHOW STATS_TOTALS", row_factory=dict_row)
    p3_stats = next(s for s in stats if s["database"] == "p3")
    assert p3_stats is not None
    # 5 connection attempts (and thus assignments)
    assert p3_stats["server_assignment_count"] == 5
    assert p3_stats["client_login_count"] == 5
    # 4 autocommit queries + 2 transactions
    assert p3_stats["xact_count"] == 6
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK
    assert p3_stats["query_count"] == 15

    totals = bouncer.admin("SHOW TOTALS")
    # 5 p3 connection attempts (and thus assignments)
    assert ("total_server_assignment_count", 5) in totals
    # 5 p3 connections + 3 admin connections from this test + 1 admin connection from Bouncer.wait_until_running()
    assert ("total_client_login_count", 9) in totals
    # 4 autocommit queries + 2 transactions + 4 admin commands
    assert ("total_xact_count", 10) in totals
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK + 4 admin commands
    assert ("total_query_count", 19) in totals
