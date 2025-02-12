import time
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest


def test_cancel(bouncer):
    with bouncer.cur(dbname="p3") as cur:
        with ThreadPoolExecutor(max_workers=2) as pool:
            query = pool.submit(cur.execute, "select pg_sleep(5)")

            time.sleep(1)

            cancel = pool.submit(cur.connection.cancel)
            cancel.result()
            with pytest.raises(
                psycopg.errors.QueryCanceled, match="due to user request"
            ):
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

    with bouncer.cur(dbname="p3") as cur:
        with ThreadPoolExecutor(max_workers=6) as pool:
            q1 = pool.submit(cur.execute, "select pg_sleep(5)")
            others = [pool.submit(bouncer.sleep, 2, dbname="p3") for _ in range(4)]

            cancel = pool.submit(cur.connection.cancel)
            cancel.result()
            with pytest.raises(
                psycopg.errors.QueryCanceled, match="due to user request"
            ):
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


# Checks that pgbouncer handles cancel requests for waiting client
def test_cancel_on_wait(bouncer):
    bouncer.admin("set default_pool_size=1")
    bouncer.admin("set log_pooler_errors=1")
    conn1 = bouncer.conn(dbname="p1")
    cur1 = conn1.cursor()
    conn2 = bouncer.conn(dbname="p1")
    cur2 = conn2.cursor()
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            q1 = pool.submit(cur1.execute, "select pg_sleep(5)")
            time.sleep(1)
            q2 = pool.submit(cur2.execute, "select pg_sleep(5)")
            time.sleep(1)

            cancel = pool.submit(conn2.cancel)
            cancel.result()
            bouncer.print_logs()

            with pytest.raises(Exception, match="Cancelled waiting query"):
                q2.result()
            q1.result()
    finally:
        conn1.close()
        conn2.close()


# Checks that pgbouncer handles cancel requests for waiting client due to pause
def test_cancel_on_wait_with_pause(bouncer):
    conn = bouncer.conn(dbname="p1")
    cur = conn.cursor()
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            bouncer.admin("pause p1")
            q = pool.submit(cur.execute, "select pg_sleep(5)")
            time.sleep(1)

            cancel = pool.submit(conn.cancel)
            cancel.result()
            bouncer.print_logs()

            with pytest.raises(Exception, match="Cancelled waiting query"):
                q.result()
    finally:
        conn.close()
        bouncer.admin("resume p1")
