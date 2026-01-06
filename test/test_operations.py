import asyncio
import time

import psycopg
import pytest

from .utils import PG_SUPPORTS_SCRAM, WINDOWS


@pytest.mark.single_thread_only
@pytest.mark.skipif("WINDOWS", reason="gets stuck for some reason during takeover")
async def test_online_restart(bouncer):
    for _ in range(5):
        # max_client_conn = 10
        # default_pool_size = 5
        task = bouncer.asleep(2, dbname="p1", times=5)
        await asyncio.sleep(0.5)
        await bouncer.reboot()
        await task


async def test_pause_resume(bouncer):
    task = bouncer.asleep(0.1, times=50, sequentially=True, connect_timeout=30)

    for _ in range(5):
        await bouncer.aadmin("pause")
        await asyncio.sleep(1)
        await bouncer.aadmin("resume")
        await asyncio.sleep(1)

    await task


async def test_suspend_resume(bouncer):
    task = bouncer.asleep(0.1, times=50, sequentially=True)

    for _ in range(5):
        async with bouncer.admin_runner.acur() as cur:
            await cur.execute("suspend")
            await asyncio.sleep(1)
            await cur.execute("resume")
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
        # WindowsSelectorEventLoopPolicy does not support async subprocesses,
        # so we fall back to regular suprocesses here.
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


@pytest.mark.single_thread_only
@pytest.mark.skipif("not PG_SUPPORTS_SCRAM")
@pytest.mark.skipif("WINDOWS", reason="gets stuck for some reason during takeover")
async def test_scram_takeover(bouncer):
    bouncer.admin("set pool_mode=transaction")
    bouncer.admin("set server_lifetime=3")
    bouncer.admin("set auth_type='scram-sha-256'")
    async with bouncer.acur(dbname="p62", user="scramuser1", password="foo") as cur:
        await cur.execute("select 1")
        await asyncio.sleep(4)  # wait for server_lifetime
        await bouncer.reboot()
        await cur.execute("select 1")
