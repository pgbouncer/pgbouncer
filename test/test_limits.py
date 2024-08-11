import asyncio
import re

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
    # per user pool_size
    await bouncer.asleep(0.5, dbname="p0a", user="poolsize1", times=3)
    assert pg.connection_count(dbname="p0", users=("poolsize1",)) == 1
    # even though we connect using user poolsize1 its setting do not apply is forced user is configured for db
    await bouncer.asleep(0.5, dbname="p0", user="poolsize1", times=5)
    assert pg.connection_count(dbname="p0", users=("bouncer",)) == 2

    # per db pool_size
    await bouncer.asleep(0.5, times=5)
    assert pg.connection_count("p0") == 2

    # global pool_size
    bouncer.default_db = "p1"
    await bouncer.asleep(0.5, times=10)
    assert pg.connection_count("p1") == 5

    # test reload (GH issue #248)
    bouncer.admin("set default_pool_size = 7")
    await bouncer.asleep(0.5, times=10)
    assert pg.connection_count("p1") == 7


@pytest.mark.asyncio
async def test_min_pool_size(pg, bouncer):
    # uncommenting the db that has "forced" maintenance enabled
    # by not having this db enabled we avoid polluting other tests
    # with connections getting autocreated
    with bouncer.ini_path.open() as f:
        original = f.read()
    with bouncer.ini_path.open("w") as f:
        # uncomment the relevant db
        new = re.sub(r"^;p0z= (.+)", r"p0z= \g<1>", original, flags=re.MULTILINE)
        print(new)
        f.write(new)
    bouncer.admin("reload")

    # having to wait a little to give janitor time to create connection to satisfy min_pool_size
    await asyncio.sleep(2)

    # ensure db without min_pool_size has no connections
    # p0
    assert pg.connection_count(dbname="p0", users=("bouncer",)) == 0
    # ensure db with min_pool_size and forced user (p0z) has the required
    # backend connections
    assert pg.connection_count(dbname="p0", users=("pswcheck",)) == 3

    # ensure db with min_pool_size and no forced user (p0x) has no backend
    # connections
    assert pg.connection_count(dbname="p0", users=("postgres",)) == 0
    # client connecting to p0x should trigger backend connection creation up to
    # min_pool_size.
    #
    # NOTE: It's a bit tricky to get the timing of this test to work
    # robustly: Full maintenance runs three times a second, so we
    # need to wait at least 1/3 seconds for it to notice for sure
    # that the pool is in use.  When it does, it will launch one
    # connection per round, so we need to wait at least 3 * 1/3
    # second before all the min pool connections are launched.
    # Also, we need to keep the query running while this is
    # happening so that the pool doesn't become momentarily
    # unused.
    result = bouncer.asleep(2, dbname="p0x")
    await asyncio.sleep(2)
    await result
    assert pg.connection_count(dbname="p0", users=("postgres",)) == 5


@pytest.mark.asyncio
async def test_max_user_client_connections_positive(bouncer):
    result = bouncer.asleep(6, user="maxedout3")
    await asyncio.sleep(1)
    users = bouncer.admin("SHOW USERS")
    user = [user for user in users if user[0] == "maxedout3"][0]
    assert user == ("maxedout3", "", None, 0, 0, 2, 1)

    # should still be allowed, since it's the last allowed connection
    await bouncer.atest(user="maxedout3")
    await result

@pytest.mark.asyncio
async def test_max_user_client_connections_negative(bouncer):
    result = bouncer.asleep(3, user="maxedout3")
    result_last = bouncer.asleep(3, user="maxedout3")
    await asyncio.sleep(1)
    users = bouncer.admin("SHOW USERS")
    user = [user for user in users if user[0] == "maxedout3"][0]
    assert user == ("maxedout3", "", None, 0, 0, 2, 2)
    with pytest.raises(psycopg.OperationalError, match=r"max_user_client_connections"):
        await bouncer.atest(user="maxedout3")
    await result
    await result_last


def test_min_pool_size_with_lower_max_user_connections(bouncer):
    # The p0x in test.init has min_pool_size set to 5. This should make
    # the PgBouncer try to create a pool for maxedout2 user of size 5 after a
    # client connects to the PgBouncer. However maxedout2 user has
    # max_user_connections set to 2, so the final pool size should be only 2.

    # Running a query for sufficient time for us to reach the final
    # connection count in the pool and detect any evictions.
    with bouncer.log_contains(r"new connection to server \(from", times=2):
        with bouncer.log_contains("closing because: evicted", times=0):
            bouncer.sleep(2, dbname="p0x", user="maxedout2")


def test_min_pool_size_with_lower_max_db_connections(bouncer):
    # The p0x in test.init has min_pool_size set to 5. This should make
    # the PgBouncer try to create a pool for puser1 user of size 5 after a client
    # connects to the PgBouncer. However the db also has max_db_connections set
    # to 2, so the final pool size should be only 2.

    # Running a query for sufficient time for us to reach the final
    # connection count in the pool and detect any evictions.
    with bouncer.log_contains(r"new connection to server \(from", times=2):
        with bouncer.log_contains("closing because: evicted", times=0):
            bouncer.sleep(2, dbname="p0y", user="puser1")


@pytest.mark.asyncio
async def test_reserve_pool_size(pg, bouncer):
    bouncer.admin("set reserve_pool_size = 3")
    bouncer.admin("set reserve_pool_timeout = 2")

    # Disable tls to get more consistent timings
    bouncer.admin("set server_tls_sslmode = disable")

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
