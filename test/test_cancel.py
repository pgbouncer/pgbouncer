import time
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest
from psycopg.rows import dict_row

from .utils import FREEBSD, LINUX, wait_until


def test_cancel(bouncer):
    with bouncer.cur(dbname="p3") as cur, ThreadPoolExecutor(max_workers=2) as pool:
        query = pool.submit(cur.execute, "select pg_sleep(5)")

        time.sleep(1)

        cancel = pool.submit(cur.connection.cancel)
        cancel.result()
        with pytest.raises(psycopg.errors.QueryCanceled, match="due to user request"):
            query.result()


# Test for waiting connections handling for cancel requests.
#
# The bug fixed by GH PR #542 was: When the connection pool is full,
# cancel requests cannot get through (that is normal), but then when
# unused connections close and pool slots are available, those are not
# used for waiting cancel requests.
def test_cancel_wait(bouncer):
    # default_pool_size=5
    bouncer.admin(f"set server_idle_timeout=2")

    with bouncer.cur(dbname="p3") as cur, ThreadPoolExecutor(max_workers=6) as pool:
        q1 = pool.submit(cur.execute, "select pg_sleep(5)")
        others = [pool.submit(bouncer.sleep, 2, dbname="p3") for _ in range(4)]

        cancel = pool.submit(cur.connection.cancel)
        cancel.result()
        with pytest.raises(psycopg.errors.QueryCanceled, match="due to user request"):
            q1.result()

        for q in others:
            q.result()


# Test that cancel requests can exceed the pool size
#
# Cancel request connections can use twice the pool size.  See also GH
# PR #543.
def test_cancel_pool_size(bouncer):
    # default_pool_size=5
    bouncer.admin(f"set server_idle_timeout=2")

    with ThreadPoolExecutor(max_workers=10) as pool:
        conns = [bouncer.conn(dbname="p3") for _ in range(5)]
        try:
            queries = [
                pool.submit(conn.cursor().execute, "select pg_sleep(20)")
                for conn in conns
            ]
            time.sleep(1)
            cancels = [pool.submit(conn.cancel) for conn in conns]

            for c in cancels:
                c.result()
            for q in queries:
                with pytest.raises(
                    psycopg.errors.QueryCanceled, match="due to user request"
                ):
                    q.result()
        finally:
            for conn in conns:
                conn.close()


# Test that cancel requests connections don't trigger cancellation of a query
# from a different client.
#
# See also GH PR #717. Prior to this change it was possible to that a query was
# cancelled on client A by a cancellation for client B, if the server was
# released by client B and then reused by client A while the cancellation was
# already in flight.
def test_cancel_race(bouncer):
    # Make sure only one query can run at the same time so that its ensured
    # that both clients will use the same server connection.
    bouncer.admin("set default_pool_size=1")
    bouncer.admin("set server_idle_timeout=2")
    bouncer.admin("set verbose=1")
    conn1 = bouncer.conn(dbname="p1")
    cur1 = conn1.cursor()
    conn2 = bouncer.conn(dbname="p1")
    cur2 = conn2.cursor()
    try:
        with ThreadPoolExecutor(max_workers=100) as pool:
            q1 = pool.submit(cur1.execute, "select pg_sleep(5)")
            time.sleep(1)
            q2 = pool.submit(cur2.execute, "select pg_sleep(1)")
            time.sleep(1)

            cancels = [pool.submit(conn1.cancel) for _ in range(100)]

            # Spam many concurrent cancel requests to try and with the goal of
            # triggering race conditions
            for c in cancels:
                c.result()

            with pytest.raises(
                psycopg.errors.QueryCanceled, match="due to user request"
            ):
                q1.result()
            q2.result()
            bouncer.print_logs()
    finally:
        conn1.close()
        conn2.close()


def send_query_without_waiting(bouncer, query, **kwargs):
    """Open a connection and send a query without reading the result"""
    conn = bouncer.conn(**kwargs)
    conn.pgconn.send_query(query.encode())
    while conn.pgconn.flush() != 0:
        time.sleep(0.01)
    return conn


def wait_for_pool(bouncer, dbname, **expected):
    """Wait until SHOW POOLS reports the expected counts for the database"""
    for _ in wait_until(f"pool {dbname} did not reach {expected}"):
        pools = bouncer.admin("show pools", row_factory=dict_row)
        pools = [p for p in pools if p["database"] == dbname]
        if pools and all(pools[0][k] == v for k, v in expected.items()):
            return


def read_value(conn):
    """Read the result of a query sent with send_query_without_waiting"""
    result = conn.pgconn.get_result()
    assert result.status == psycopg.pq.ExecStatus.TUPLES_OK
    value = result.get_value(0, 0)
    assert conn.pgconn.get_result() is None
    return value


# Postgrex handles a query timeout by sending a cancel request, then a
# Terminate message, and then it closes the socket. If the query is still
# waiting for a server, PgBouncer must not give the client a server. It would
# send the canceled query, see the client disconnect, and close the server.
@pytest.mark.skipif(
    "not (LINUX or FREEBSD)", reason="needs POLLRDHUP to see the disconnect"
)
def test_cancel_waiting_client_then_disconnect(bouncer):
    bouncer.admin("set default_pool_size=1")
    with ThreadPoolExecutor(max_workers=1) as pool:
        busy = pool.submit(
            bouncer.sql_value, "select pg_backend_pid() from pg_sleep(1)", dbname="p3x"
        )
        wait_for_pool(bouncer, "p3x", sv_active=1)
        conn = send_query_without_waiting(bouncer, "select 1", dbname="p3x")
        wait_for_pool(bouncer, "p3x", cl_waiting=1)

        with (
            bouncer.log_contains(
                "client canceled query and closed connection while waiting", times=1
            ),
            bouncer.log_contains(
                "client disconnect while server was not ready", times=0
            ),
        ):
            conn.cancel()
            conn.pgconn.finish()
            busy_pid = busy.result()
            wait_for_pool(bouncer, "p3x", cl_waiting=0, sv_active=0)

    # the server that ran the busy query was not closed
    assert bouncer.sql_value("select pg_backend_pid()", dbname="p3x") == busy_pid


# Several canceled and disconnected clients wait in front of a live one. When
# the server is released, it must skip the dropped clients and go to the live
# client.
@pytest.mark.skipif(
    "not (LINUX or FREEBSD)", reason="needs POLLRDHUP to see the disconnect"
)
def test_cancel_waiting_clients_before_live_client(bouncer):
    bouncer.admin("set default_pool_size=1")
    with ThreadPoolExecutor(max_workers=1) as pool:
        busy = pool.submit(
            bouncer.sql_value, "select pg_backend_pid() from pg_sleep(1)", dbname="p3x"
        )
        wait_for_pool(bouncer, "p3x", sv_active=1)
        gone = [
            send_query_without_waiting(bouncer, "select 1", dbname="p3x")
            for _ in range(3)
        ]
        wait_for_pool(bouncer, "p3x", cl_waiting=3)
        live = send_query_without_waiting(
            bouncer, "select pg_backend_pid()", dbname="p3x"
        )
        wait_for_pool(bouncer, "p3x", cl_waiting=4)

        with bouncer.log_contains(
            "client canceled query and closed connection while waiting", times=3
        ):
            for conn in gone:
                conn.cancel()
                conn.pgconn.finish()
            busy_pid = busy.result()
            assert int(read_value(live)) == busy_pid
        live.close()


# A client that cancels a waiting query but stays connected still gets the
# result, like with a cancel request that arrives before the query starts.
def test_cancel_waiting_client_stays_connected(bouncer):
    bouncer.admin("set default_pool_size=1")
    with ThreadPoolExecutor(max_workers=1) as pool:
        busy = pool.submit(bouncer.sleep, 1, dbname="p3x")
        wait_for_pool(bouncer, "p3x", sv_active=1)
        conn = send_query_without_waiting(bouncer, "select 1", dbname="p3x")
        try:
            wait_for_pool(bouncer, "p3x", cl_waiting=1)
            conn.cancel()
            busy.result()
            assert read_value(conn) == b"1"
            assert conn.execute("select 2").fetchone()[0] == 2
        finally:
            conn.close()


# A cancel for an earlier waiting query must not affect a later one. Without
# a cancel request, a waiting client that disconnects takes the old path.
def test_cancel_waiting_client_is_forgotten(bouncer):
    bouncer.admin("set default_pool_size=1")
    with ThreadPoolExecutor(max_workers=1) as pool:
        busy = pool.submit(bouncer.sleep, 1, dbname="p3x")
        wait_for_pool(bouncer, "p3x", sv_active=1)
        conn = send_query_without_waiting(bouncer, "select 1", dbname="p3x")
        wait_for_pool(bouncer, "p3x", cl_waiting=1)
        conn.cancel()
        busy.result()
        assert read_value(conn) == b"1"

        busy = pool.submit(bouncer.sleep, 1, dbname="p3x")
        wait_for_pool(bouncer, "p3x", sv_active=1)
        conn.pgconn.send_query(b"select 2")
        while conn.pgconn.flush() != 0:
            time.sleep(0.01)
        wait_for_pool(bouncer, "p3x", cl_waiting=1)
        with bouncer.log_contains(
            "client canceled query and closed connection while waiting", times=0
        ):
            conn.pgconn.finish()
            busy.result()
            wait_for_pool(bouncer, "p3x", cl_waiting=0, sv_active=0)


# Same as above, but the clients wait during PAUSE. PAUSE closes the servers,
# so after RESUME the clients are woken when a new server finishes its login.
@pytest.mark.skipif(
    "not (LINUX or FREEBSD)", reason="needs POLLRDHUP to see the disconnect"
)
def test_cancel_waiting_client_then_disconnect_paused(bouncer):
    bouncer.admin("set default_pool_size=1")
    bouncer.sql_value("select 1", dbname="p3x")
    bouncer.admin("pause p3x")
    gone = send_query_without_waiting(bouncer, "select 1", dbname="p3x")
    live = send_query_without_waiting(bouncer, "select 42", dbname="p3x")
    wait_for_pool(bouncer, "p3x", cl_waiting=2)
    with (
        bouncer.log_contains(
            "client canceled query and closed connection while waiting", times=1
        ),
        bouncer.log_contains("client disconnect while server was not ready", times=0),
    ):
        gone.cancel()
        gone.pgconn.finish()
        bouncer.admin("resume p3x")
        assert read_value(live) == b"42"
    live.close()
