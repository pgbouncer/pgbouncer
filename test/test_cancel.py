import time
from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory

import psycopg
import pytest

from .utils import (
    MACOS,
    USE_SUDO,
    USE_UNIX_SOCKETS,
    Postgres,
    sudo,
    wait_until,
)


def start_second_postgres(pg, tmp_path, host, conf):
    """Start another server on pg's port, reachable only at host"""
    other = Postgres(tmp_path / "second_pgdata")
    other.initdb()
    other.host = host
    other.port = pg.port
    with other.conf_path.open("a") as pgconf:
        pgconf.write(conf)
    other.nossl_access("all", "trust")
    with other.hba_path.open("a") as pghba:
        # macOS connects to a loopback alias from that same address
        pghba.write("hostnossl all all samehost trust\n")
    other.commit_hba()
    other.start()
    other.sql("CREATE DATABASE p0")
    other.sql("CREATE USER bouncer")
    return other


@pytest.fixture
def second_postgres(pg, tmp_path):
    conf = "listen_addresses = '127.0.0.2'\n"
    if USE_UNIX_SOCKETS:
        conf += "unix_socket_directories = ''\n"
    if MACOS:
        if not USE_SUDO:
            pytest.skip("macOS assigns only 127.0.0.1 to lo0")
        sudo("ifconfig lo0 alias 127.0.0.2 up")
    try:
        other = start_second_postgres(pg, tmp_path, "127.0.0.2", conf)
        yield other
        other.cleanup()
    finally:
        if MACOS:
            sudo("ifconfig lo0 -alias 127.0.0.2")


@pytest.fixture
def second_unix_postgres(pg, tmp_path):
    # tmp_path is too long for a socket path on macOS
    with TemporaryDirectory(dir="/tmp") as socket_dir:
        conf = f"listen_addresses = ''\nunix_socket_directories = '{socket_dir}'\n"
        other = start_second_postgres(pg, tmp_path, socket_dir, conf)
        yield other
        other.cleanup()


def test_cancel(bouncer):
    with bouncer.cur(dbname="p3") as cur, ThreadPoolExecutor(max_workers=2) as pool:
        query = pool.submit(cur.execute, "select pg_sleep(5)")

        time.sleep(1)

        cancel = pool.submit(cur.connection.cancel)
        cancel.result()
        with pytest.raises(psycopg.errors.QueryCanceled, match="due to user request"):
            query.result()


def assert_cancel_reaches_query_backend(bouncer, pg, dbname):
    with (
        bouncer.cur(dbname=dbname) as cur,
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        query = pool.submit(cur.execute, "SELECT pg_sleep(2)")

        for _ in wait_until("query did not reach the first host"):
            sleeping = pg.sql_value("""
                SELECT count(*) FROM pg_stat_activity
                WHERE usename = 'bouncer' AND datname = 'p0'
                  AND state = 'active' AND wait_event = 'PgSleep'
            """)
            if sleeping == 1:
                break

        pool.submit(cur.connection.cancel).result()
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
