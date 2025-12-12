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


def test_cancel_race_v2(bouncer):
    # Make sure only one query can run at the same time so that its ensured
    # that both clients will use the same server connection.

    # Idea: we will use dblink and native SQL features to syncronization.

    bouncer.admin("set default_pool_size=1")
    bouncer.admin("set server_idle_timeout=2")
    bouncer.admin("set verbose=1")

    conn0 = None
    conn1 = None
    conn2 = None

    try:
        cn0_str = "host={} port={} dbname={} user={}".format(
            bouncer.pg.host,
            bouncer.pg.port,
            "p0",
            "postgres",
        )

        conn0 = psycopg.connect(cn0_str, autocommit=True)
        conn1 = bouncer.conn(dbname="p0p")
        cur1 = conn1.cursor()
        conn2 = bouncer.conn(dbname="p0p")
        cur2 = conn2.cursor()

        sql1 = """DO $$
BEGIN
    /* It locks conn2 */
    UPDATE test_cancel_race_v2 SET data='aaa' WHERE id=1;
    /* It is a signal "we are within server" in an autonomous transaction */
    PERFORM dblink_exec('{}', 'INSERT INTO test_cancel_race_v2 (id) VALUES (2);');
    /* Cancel signal is waited */
    PERFORM pg_sleep(60);
END $$;""".format(
            cn0_str
        )

        with ThreadPoolExecutor(max_workers=100) as pool:
            conn1.execute(
                "CREATE TABLE test_cancel_race_v2\n"
                "(id INTEGER NOT NULL PRIMARY KEY,\n"
                "data VARCHAR(32));"
            )
            conn1.execute("INSERT INTO test_cancel_race_v2 (id) VALUES (1);")
            conn0.execute("CREATE EXTENSION dblink SCHEMA public;")

            print("Run task1 on conn1")
            q1 = pool.submit(cur1.execute, sql1)

            while True:
                print("Waits for signal from conn1")
                r = cur2.execute(
                    "SELECT id FROM test_cancel_race_v2 WHERE id=2;"
                ).fetchall()
                if len(r) == 1:
                    assert r[0][0] == 2
                    break
                assert len(r) == 0

                # There were attempts to check a state
                # of task1 via "q1.result(0.2)"" but they
                # had problems on GitHub CI. So it the most easier
                # and stable variant.

                print("Sleep a bit")
                time.sleep(0.2)
                break

            # It waits for conn1
            print("Run task2 on conn2")
            q2 = pool.submit(
                cur2.execute, "UPDATE test_cancel_race_v2 SET data='bbb' WHERE id=1;"
            )

            print("Run cancels")
            cancels = [pool.submit(conn1.cancel) for _ in range(100)]

            # Spam many concurrent cancel requests to try and with the goal of
            # triggering race conditions
            print("Wait for cancels")
            for c in cancels:
                c.result()

            print("Check task1")
            with pytest.raises(
                psycopg.errors.QueryCanceled, match="due to user request"
            ):
                q1.result()

            print("Check task2")
            q2.result()

            r = cur2.execute(
                "SELECT data FROM test_cancel_race_v2 WHERE id=1;"
            ).fetchall()
            assert r == [("bbb",)]

            bouncer.print_logs()
    finally:
        if conn0 is not None:
            conn0.close()
        if conn1 is not None:
            conn1.close()
        if conn2 is not None:
            conn2.close()
