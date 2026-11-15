import asyncio
import time

import psycopg
import pytest
from psycopg.rows import dict_row

from .utils import WINDOWS, wait_until


async def test_pause_resume(bouncer):
    task = bouncer.asleep(0.1, times=50, sequentially=True, connect_timeout=30)

    for _ in range(5):
        await bouncer.aadmin("pause")
        await asyncio.sleep(1)
        await bouncer.aadmin("resume")
        await asyncio.sleep(1)

    await task


async def wait_for_admin_row(bouncer, query, **expected):
    for _ in wait_until(f"{query} has no row matching {expected}", interval=0):
        rows = await bouncer.aadmin(query, row_factory=dict_row)
        if any(expected.items() <= row.items() for row in rows):
            return
        await asyncio.sleep(0.1)


async def test_resume_cancels_pending_pause(bouncer):
    """RESUME p0 must answer a pending PAUSE p0, but not WAIT_CLOSE p0 (#715)."""
    sleep_task = bouncer.asleep(5, dbname="p0")
    await wait_for_admin_row(bouncer, "SHOW SERVERS", database="p0", state="active")
    await bouncer.aadmin("RECONNECT p0")
    wait_close_task = bouncer.aadmin("WAIT_CLOSE p0")
    for _ in wait_until("WAIT_CLOSE p0 was not issued", interval=0):
        if "WAIT_CLOSE 'p0' command issued" in bouncer.log_path.read_text():
            break
        await asyncio.sleep(0.1)
    pause_task = bouncer.aadmin("PAUSE p0")
    await wait_for_admin_row(bouncer, "SHOW DATABASES", name="p0", paused=1)

    await bouncer.aadmin("RESUME p0")

    with pytest.raises(
        psycopg.errors.ProtocolViolation, match=r"^PAUSE command canceled by RESUME$"
    ):
        await asyncio.wait_for(pause_task, timeout=5)
    _, pending = await asyncio.wait([wait_close_task], timeout=0.5)
    assert wait_close_task in pending, "RESUME p0 completed WAIT_CLOSE p0"
    await sleep_task
    await wait_close_task


async def test_resume_does_not_complete_foreign_pending_pause(bouncer):
    sleep_task = bouncer.asleep(5, dbname="p1")
    await wait_for_admin_row(bouncer, "SHOW SERVERS", database="p1", state="active")
    pause_task = bouncer.aadmin("PAUSE p1")
    await wait_for_admin_row(bouncer, "SHOW DATABASES", name="p1", paused=1)

    await bouncer.aadmin("PAUSE p0")
    await bouncer.aadmin("RESUME p0")

    _, pending = await asyncio.wait([pause_task], timeout=0.5)
    assert pause_task in pending, "RESUME p0 completed or canceled PAUSE p1"
    await sleep_task
    await pause_task


async def test_global_resume_cancels_pending_global_pause(bouncer):
    sleep_task = bouncer.asleep(5, dbname="p1")
    await wait_for_admin_row(bouncer, "SHOW SERVERS", database="p1", state="active")
    db_pause_task = bouncer.aadmin("PAUSE p1")
    await wait_for_admin_row(bouncer, "SHOW DATABASES", name="p1", paused=1)
    pause_task = bouncer.aadmin("PAUSE")
    await wait_for_admin_row(bouncer, "SHOW STATE", key="paused", value="yes")

    await bouncer.aadmin("RESUME")

    with pytest.raises(
        psycopg.errors.ProtocolViolation, match=r"^PAUSE command canceled by RESUME$"
    ):
        await asyncio.wait_for(pause_task, timeout=5)
    _, pending = await asyncio.wait([db_pause_task], timeout=0.5)
    assert db_pause_task in pending, "global RESUME canceled PAUSE p1"
    await sleep_task
    await db_pause_task


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGUSR2")
async def test_sigusr2_cancels_pending_pause(bouncer):
    sleep_task = bouncer.asleep(5, dbname="p0")
    await wait_for_admin_row(bouncer, "SHOW SERVERS", database="p0", state="active")
    pause_task = bouncer.aadmin("PAUSE")
    await wait_for_admin_row(bouncer, "SHOW STATE", key="paused", value="yes")

    bouncer.sigusr2()

    with pytest.raises(
        psycopg.errors.ProtocolViolation, match=r"^PAUSE command canceled by RESUME$"
    ):
        await asyncio.wait_for(pause_task, timeout=5)
    await sleep_task


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
