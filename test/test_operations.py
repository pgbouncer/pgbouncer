import asyncio
import time

import psycopg
import pytest

from .utils import PG_MAJOR_VERSION, WINDOWS, wait_until


async def test_pause_resume(bouncer):
    task = bouncer.asleep(0.1, times=50, sequentially=True, connect_timeout=30)

    for _ in range(5):
        await bouncer.aadmin("pause")
        await asyncio.sleep(1)
        await bouncer.aadmin("resume")
        await asyncio.sleep(1)

    await task


def test_enable_disable(bouncer):
    bouncer.test()
    bouncer.admin("disable p0")

    with pytest.raises(
        psycopg.OperationalError,
        match=r'database "p0" is disabled',
    ):
        bouncer.test()
    bouncer.admin("enable p0")
    bouncer.test()


async def test_database_restart(pg, bouncer):
    bouncer.admin("set server_login_retry=1")
    bouncer.test()
    pg.restart()
    bouncer.test()

    tasks = []
    for i in range(1, 6):
        tasks.append(bouncer.asleep(i, dbname="p0"))
        tasks.append(bouncer.asleep(i, dbname="p1"))

    await asyncio.sleep(0.5)
    if WINDOWS:
        # The SelectorEventLoop does not support async subprocesses, so we fall
        # back to regular subprocesses here.
        pg.restart()
    else:
        await pg.arestart()
    for task in tasks:
        try:
            await task
        except psycopg.OperationalError:
            pass
    bouncer.test(dbname="p0")
    bouncer.test(dbname="p1")


def in_hot_standby(bouncer):
    # Only look at the value from the login, a query would update it
    with bouncer.conn(dbname="p3") as conn:
        return conn.info.parameter_status("in_hot_standby")


def wait_for_in_hot_standby(bouncer, value, timeout=5):
    for _ in wait_until(f"in_hot_standby={value} not reported", timeout=timeout):
        try:
            if in_hot_standby(bouncer) == value:
                return
        except psycopg.OperationalError:
            pass


def restart_as_standby(pg, bouncer):
    pg.stop()
    (pg.pgdata / "standby.signal").touch()
    pg.start()
    # A query replaces the server connections that the restart killed, the
    # new server login reports in_hot_standby=on
    for _ in wait_until("PgBouncer did not reconnect"):
        try:
            bouncer.test(dbname="p3")
            break
        except psycopg.OperationalError:
            pass


@pytest.mark.skipif(PG_MAJOR_VERSION < 14, reason="in_hot_standby was added in PG14")
def test_in_hot_standby_after_promote(pg, bouncer):
    """
    New clients must not keep getting a cached in_hot_standby=on after the
    server got promoted. PgBouncer picks up the new value from new server
    logins and from existing server connections running a query.
    """
    bouncer.admin("set server_login_retry=1")
    try:
        # Promotion while the pooled server connection stays open
        restart_as_standby(pg, bouncer)
        wait_for_in_hot_standby(bouncer, "on")
        pg.sql("SELECT pg_promote()")
        bouncer.test(dbname="p3")
        assert in_hot_standby(bouncer) == "off"

        # Promotion where all the server connections are closed
        restart_as_standby(pg, bouncer)
        wait_for_in_hot_standby(bouncer, "on")
        pg.sql("SELECT pg_promote()")
        pg.sql(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'bouncer'"
        )
        for _ in wait_until("PgBouncer did not reconnect"):
            try:
                bouncer.test(dbname="p3")
                break
            except psycopg.OperationalError:
                pass
        assert in_hot_standby(bouncer) == "off"
    finally:
        if pg.sql_value("SELECT pg_is_in_recovery()"):
            pg.sql("SELECT pg_promote()")


def test_database_change(bouncer):
    bouncer.admin("set server_lifetime=2")
    bouncer.default_db = "p1"
    assert bouncer.sql_value("select current_database()") == "p1"

    with bouncer.ini_path.open() as f:
        original = f.read()
    with bouncer.ini_path.open("w") as f:
        f.write(original.replace("dbname=p1", "dbname=p0"))
    bouncer.admin("reload")
    time.sleep(3)

    assert bouncer.sql_value("select current_database()") == "p0"


def test_reconnect(bouncer):
    pid1 = bouncer.sql_value("select pg_backend_pid()")

    bouncer.admin("reconnect")
    time.sleep(1)

    pid2 = bouncer.sql_value("select pg_backend_pid()")
    assert pid1 != pid2
