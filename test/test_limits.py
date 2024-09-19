import asyncio
import re

import psycopg
from psycopg.rows import dict_row
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
async def test_max_db_client_connections_local_override_global(bouncer):
    """Test that database level max_db_client_connections overrides server level max_db_client_connections."""
    config = f"""
    [databases]
    conn_limit_db = port={bouncer.pg.port} host=127.0.0.1 dbname=p0 max_db_client_connections=2

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    auth_user = pgbouncer
    auth_dbname = postgres
    admin_users = pgbouncer
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    max_db_client_connections = 3
    """
    with bouncer.run_with_config(config):
        test_db = "conn_limit_db"
        connect_args = {"dbname": test_db, "user": "muser1"}
        conns = [bouncer.conn(**connect_args) for _ in range(2)]
        dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
        db = [db for db in dbs if db["name"] == test_db][0]
        assert db["current_client_connections"] == 2
        assert db["max_client_connections"] == 2
        with pytest.raises(
            psycopg.OperationalError, match=r"max_db_client_connections"
        ):
            test_conn = bouncer.conn(**connect_args)
        with pytest.raises(
            psycopg.OperationalError, match=r"max_db_client_connections"
        ):
            test_conn = bouncer.conn(**connect_args)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "muser1"),
        ("pgbouncer", "pgbouncer"),
        ("pgbouncer", "muser1"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
async def test_max_db_client_connections_global_negative(
    bouncer, test_db: str, test_user: str
) -> None:
    """Negative test of server wide max_db_client_connections setting."""
    config = f"""
    [databases]
    p0 = port={bouncer.pg.port} host=127.0.0.1 dbname=p0
    authdb = port={bouncer.pg.port} host=127.0.0.1 dbname=p0 auth_user=pswcheck

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    auth_user = pgbouncer
    admin_users = pgbouncer
    stats_users = muser1
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    max_db_client_connections = 2
    """
    with bouncer.run_with_config(config):
        connect_args = {"dbname": test_db, "user": test_user}
        conns = [bouncer.conn(**connect_args) for _ in range(2)]
        dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
        db = [db for db in dbs if db["name"] == test_db][0]
        assert db["current_client_connections"] == 2 if test_db == "p0" else 3
        assert db["max_client_connections"] == 2

        if test_db == "pgbouncer" and test_user == "pgbouncer":
            err_con = bouncer.conn(**connect_args)
        else:
            with pytest.raises(
                psycopg.OperationalError, match=r"max_db_client_connections"
            ):
                err_con = bouncer.conn(**connect_args)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "muser1"),
        ("pgbouncer", "pgbouncer"),
        ("pgbouncer", "muser1"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
async def test_max_db_client_connections_global_positive(
    bouncer, test_db: str, test_user: str
) -> None:
    """Positive test of server wide max_db_client_connections setting."""
    config = f"""
    [databases]
    p0 = port={bouncer.pg.port} host=127.0.0.1 dbname=p0
    authdb = port={bouncer.pg.port} host=127.0.0.1 dbname=p0 auth_user=pswcheck

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    auth_user = pgbouncer
    admin_users = pgbouncer
    stats_users = muser1
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    max_db_client_connections = 2
    """
    with bouncer.run_with_config(config):
        connect_args = {"dbname": test_db, "user": test_user}
        con = bouncer.conn(**connect_args)
        # should still be allowed, since it's the last allowed connection
        dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
        db = [db for db in dbs if db["name"] == test_db][0]
        assert db["current_client_connections"] == 1 if test_db == "p0" else 2
        assert db["max_client_connections"] == 2
        err_con = bouncer.conn(**connect_args)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "muser1"),
        ("pgbouncer", "pgbouncer"),
        ("pgbouncer", "muser1"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_db_client_connections_decrement(
    bouncer, test_db: str, test_user: str
) -> None:
    """Test that max_db_connections is correctly decremented when user closes connection."""
    config = f"""
    [databases]
    p0 = port={bouncer.pg.port} host=127.0.0.1 dbname=p0
    authdb = port={bouncer.pg.port} host=127.0.0.1 dbname=p0 auth_user=pswcheck

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    auth_user = pgbouncer
    admin_users = pgbouncer
    stats_users = muser1
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    max_db_client_connections = 2
    """
    with bouncer.run_with_config(config):
        connect_args = {"dbname": test_db, "user": test_user}
        [conn_1, conn_2] = [bouncer.conn(**connect_args) for _ in range(2)]
        dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
        db = [db for db in dbs if db["name"] == test_db][0]
        assert db["current_client_connections"] == 2 if test_db == "p0" else 3

        conn_2.close()
        dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
        db = [db for db in dbs if db["name"] == test_db][0]
        assert db["current_client_connections"] == 1 if test_db == "p0" else 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "muser1"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
async def test_max_db_client_connections_negative(
    bouncer, test_db: str, test_user: str
) -> None:
    """Negative test of database specific max_db_client_connections setting."""
    config = f"""
    [databases]
    p0 = port={bouncer.pg.port} host=127.0.0.1 dbname=p0 max_db_client_connections=2
    authdb = port={bouncer.pg.port} host=127.0.0.1 dbname=p0 auth_user=pswcheck max_db_client_connections=2

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    auth_user = pgbouncer
    admin_users = pgbouncer
    stats_users = muser1
    logfile = {bouncer.log_path}
    auth_file = {bouncer.auth_path}
    """
    connect_args = {"dbname": test_db, "user": test_user}
    with bouncer.run_with_config(config):
        conns = [bouncer.conn(**connect_args) for _ in range(2)]
        dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
        db = [db for db in dbs if db["name"] == test_db][0]
        assert db["current_client_connections"] == 2 if test_db == "p0" else 3
        assert db["max_client_connections"] == 2

        with pytest.raises(
            psycopg.OperationalError, match=r"max_db_client_connections"
        ):
            bouncer.conn(**connect_args)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "muser1"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
async def test_max_db_client_connections_positive(
    bouncer, test_db: str, test_user
) -> None:
    """Positive test of database specific max_db_client_connections setting."""
    config = f"""
    [databases]
    p0 = port={bouncer.pg.port} host=127.0.0.1 dbname=p0 max_db_client_connections=2
    authdb = port={bouncer.pg.port} host=127.0.0.1 dbname=p0 auth_user=pswcheck max_db_client_connections=2

    [pgbouncer]
    listen_addr = {bouncer.host}
    listen_port = {bouncer.port}
    auth_type = trust
    auth_file = userlist.txt
    auth_user = pgbouncer
    admin_users = pgbouncer
    stats_users = muser1
    logfile = {bouncer.log_path}
    """
    connect_args = {"dbname": test_db, "user": test_user}
    with bouncer.run_with_config(config):
        conn_1 = bouncer.conn(**connect_args)
        # should still be allowed, since it's the last allowed connection
        dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
        db = [db for db in dbs if db["name"] == test_db][0]
        assert db["current_client_connections"] == 1 if test_db == "p0" else 2
        assert db["max_client_connections"] == 2
        conn_2 = bouncer.conn(**connect_args)


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
