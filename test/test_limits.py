import asyncio

import psycopg
import pytest


@pytest.mark.asyncio
async def test_max_client_conn(bouncer):
    bouncer.default_db = "p1"
    bouncer.admin(f"set max_client_conn=5")
    result = bouncer.asleep(3, times=4)
    await asyncio.sleep(1)
    # should still be allowed, since it's the last allowed connection
    await bouncer.atest()
    result_last = bouncer.asleep(3)
    await asyncio.sleep(1)
    with pytest.raises(psycopg.OperationalError, match=r"max_client_conn"):
        await bouncer.atest()
    await result
    await result_last


@pytest.mark.asyncio
async def test_pool_size(pg, bouncer):
    await bouncer.asleep(0.5, times=10)
    assert pg.connection_count("p0") == 2

    bouncer.default_db = "p1"
    await bouncer.asleep(0.5, times=10)
    assert pg.connection_count("p1") == 5

    # test reload (GH issue #248)
    bouncer.admin("set default_pool_size = 7")
    await bouncer.asleep(0.5, times=10)
    assert pg.connection_count("p1") == 7


@pytest.mark.asyncio
async def test_min_pool_size(pg, bouncer):
    bouncer.admin("set min_pool_size = 3")
    assert pg.connection_count("p1") == 0

    # It's a bit tricky to get the timing of this test to work
    # robustly: Full maintenance runs three times a second, so we
    # need to wait at least 1/3 seconds for it to notice for sure
    # that the pool is in use.  When it does, it will launch one
    # connection per round, so we need to wait at least 3 * 1/3
    # second before all the min pool connections are launched.
    # Also, we need to keep the query running while this is
    # happening so that the pool doesn't become momentarily
    # unused.
    result = bouncer.asleep(2, dbname="p1")
    await asyncio.sleep(2)
    await result
    assert pg.connection_count("p1") == 3


def test_min_pool_size_with_lower_max_user_connections(bouncer):
    # The p0x in test.init has min_pool_size set to 5. This should make
    # the PgBouncer try to create a pool for maxedout2 user of size 5 after a
    # client connects to the PgBouncer. However maxedout2 user has
    # max_user_connections set to 2, so the final pool size should be only 2.

    # Running a query for sufficient time for us to reach the final
    # connection count in the pool and detect any evictions.
    with bouncer.log_contains("new connection to server", times=2):
        with bouncer.log_contains("closing because: evicted", times=0):
            bouncer.sleep(2, dbname="p0x", user="maxedout2")


def test_min_pool_size_with_lower_max_db_connections(bouncer):
    # The p0x in test.init has min_pool_size set to 5. This should make
    # the PgBouncer try to create a pool for puser1 user of size 5 after a client
    # connects to the PgBouncer. However the db also has max_db_connections set
    # to 2, so the final pool size should be only 2.

    # Running a query for sufficient time for us to reach the final
    # connection count in the pool and detect any evictions.
    with bouncer.log_contains("new connection to server", times=2):
        with bouncer.log_contains("closing because: evicted", times=0):
            bouncer.sleep(2, dbname="p0y", user="puser1")


@pytest.mark.asyncio
async def test_reserve_pool_size(pg, bouncer):
    bouncer.admin("set reserve_pool_size = 3")
    bouncer.admin("set reserve_pool_timeout = 2")
    with bouncer.log_contains("taking connection from reserve_pool", times=3):
        # default_pool_size is 5, so half of the connections will need to wait
        # until the reserve_pool_timeout (2 seconds) is reached. At that point
        # 3 more connections should be allowed to continue.
        result = bouncer.asleep(10, dbname="p1", times=10)
        await asyncio.sleep(1)
        assert pg.connection_count("p1") == 5
        await asyncio.sleep(8)
        assert pg.connection_count("p1") == 8
        await result


@pytest.mark.asyncio
async def test_max_db_connections(pg, bouncer):
    # some users, doesn't matter which ones
    users = ["muser1", "muser2", "puser1", "puser2", "postgres"]

    # p2 has max_db_connections=4
    await asyncio.gather(
        *[bouncer.asleep(0.5, dbname="p2", user=u, times=2) for u in users]
    )

    # p2 in PgBouncer maps to p0 in Postgres
    assert pg.connection_count("p0", users=users) == 4


@pytest.mark.asyncio
async def test_max_user_connections(pg, bouncer):
    # some users, doesn't matter which ones
    dbnames = ["p7a", "p7b", "p7c"]

    await asyncio.gather(
        *[
            bouncer.asleep(0.5, dbname=db, user="maxedout", times=3, connect_timeout=10)
            for db in dbnames
        ]
    )

    assert pg.connection_count("p7", users=["maxedout"]) == 3
