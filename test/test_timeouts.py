import asyncio
import platform
import time
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from .utils import USE_SUDO


def test_server_lifetime(pg, bouncer):
    bouncer.admin(f"set server_lifetime=2")

    bouncer.test()
    assert pg.connection_count() == 1
    time.sleep(3)
    assert pg.connection_count() == 0
    bouncer.test()


def test_server_idle_timeout(pg, bouncer):
    bouncer.admin(f"set server_idle_timeout=2")

    bouncer.test()
    assert pg.connection_count() == 1
    time.sleep(3)
    assert pg.connection_count() == 0
    bouncer.test()


def test_query_timeout(bouncer):
    bouncer.admin(f"set query_timeout=1")

    with bouncer.log_contains(r"query timeout"):
        with pytest.raises(
            psycopg.OperationalError, match=r"server closed the connection unexpectedly"
        ):
            bouncer.sleep(5)


def test_idle_transaction_timeout(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set idle_transaction_timeout=2")

    with bouncer.transaction() as cur:
        with bouncer.log_contains(r"idle transaction timeout"):
            time.sleep(3)
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly|Software caused connection abort",
            ):
                cur.execute("select 1")

    # test for GH issue #125
    with bouncer.transaction() as cur:
        cur.execute("select pg_sleep(2)").fetchone()
        time.sleep(1)
        cur.execute("select 1")


def test_client_idle_timeout(bouncer):
    bouncer.admin(f"set client_idle_timeout=2")

    with bouncer.cur() as cur:
        cur.execute("select 1")
        with bouncer.log_contains(r"client_idle_timeout"):
            time.sleep(3)
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly|Software caused connection abort",
            ):
                cur.execute("select 1")


@pytest.mark.asyncio
async def test_server_login_retry(pg, bouncer):
    bouncer.admin(f"set query_timeout=10")
    bouncer.admin(f"set server_login_retry=3")

    pg.stop()
    if platform.system() == "FreeBSD":
        # XXX: For some reason FreeBSD logs don't contain connect failed
        # For now we simply remove this check. But this warants further
        # investigation.
        await asyncio.gather(
            bouncer.atest(connect_timeout=10),
            pg.delayed_start(1),
        )
    else:
        with bouncer.log_contains("connect failed"):
            await asyncio.gather(
                bouncer.atest(connect_timeout=10),
                pg.delayed_start(1),
            )


def test_server_connect_timeout_establish(pg, bouncer):
    pg.configure("pre_auth_delay to '5s'")
    pg.reload()
    bouncer.admin("set query_timeout=3")
    bouncer.admin("set server_connect_timeout=2")
    with bouncer.log_contains(r"closing because: connect timeout"):
        with pytest.raises(psycopg.errors.OperationalError, match="query_timeout"):
            bouncer.test(connect_timeout=10)


@pytest.mark.skipif("not USE_SUDO")
def test_server_connect_timeout_drop_traffic(pg, bouncer):
    bouncer.admin("set query_timeout=3")
    bouncer.admin("set server_connect_timeout=2")
    with bouncer.log_contains(r"closing because: connect failed"):
        with pg.drop_traffic():
            with pytest.raises(psycopg.errors.OperationalError, match="query_timeout"):
                bouncer.test(connect_timeout=10)


@pytest.mark.skipif("not USE_SUDO")
@pytest.mark.skipif(
    "platform.system() != 'Linux'", reason="tcp_user_timeout is only supported on Linux"
)
def test_tcp_user_timeout(pg, bouncer):
    bouncer.admin("set tcp_user_timeout=1000")
    bouncer.admin("set query_timeout=5")
    # Make PgBouncer cache a connection to Postgres
    bouncer.test()
    # without tcp_user_timeout, you get a different error message
    # about "query timeout" instead
    with bouncer.log_contains(r"closing because: server conn crashed?"):
        with pg.reject_traffic():
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly|Software caused connection abort",
            ):
                bouncer.test(connect_timeout=10)


@pytest.mark.skipif("not USE_SUDO")
@pytest.mark.asyncio
async def test_server_check_delay(pg, bouncer):
    bouncer.admin("set server_check_delay=2")
    bouncer.admin("set server_login_retry=3")
    bouncer.admin("set query_timeout=10")
    with pg.drop_traffic():
        time.sleep(3)
        query_task = bouncer.atest(connect_timeout=10)

        # We wait for 1 second to show that the query is blocked while traffic
        # is dropped.
        done, pending = await asyncio.wait([query_task], timeout=1)
        assert done == set()
        assert pending == {query_task}
    await query_task


@pytest.mark.skipif("not USE_SUDO")
def test_cancel_wait_timeout(pg, bouncer):
    bouncer.admin("set cancel_wait_timeout=1")
    with bouncer.cur() as cur:
        with ThreadPoolExecutor(max_workers=2) as pool:
            query = pool.submit(cur.execute, "select pg_sleep(3)")

            time.sleep(1)

            with pg.drop_traffic():
                with bouncer.log_contains(r"closing because: cancel_wait_timeout"):
                    cancel = pool.submit(cur.connection.cancel)
                    cancel.result()

            query.result()
