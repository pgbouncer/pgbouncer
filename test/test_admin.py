import psycopg
import pytest
from psycopg.rows import dict_row

from .utils import capture, run


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


def test_kill_client_nonexisting(bouncer):
    # Connect to client as user A
    conn_1 = bouncer.conn(dbname="p0", user="maxedout")

    # Validate count
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 2

    # Get clients id
    client_id = [client for client in clients if client[2] == "p0"][0][-6]
    fake_client_id = hex(int(client_id, 16) + 1)

    # Issue kill client command
    with pytest.raises(
        psycopg.errors.ProtocolViolation,
        match=r"client not found",
    ):
        clients = bouncer.admin(f"KILL_CLIENT {fake_client_id}")

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
    clients = bouncer.admin("SHOW CLIENTS")
    assert len(clients) == 2

    # Get clients id
    client_id = [client for client in clients if client[2] == "p0"][0][-6]

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
