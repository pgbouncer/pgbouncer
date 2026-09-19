import asyncio
import os
import re
import time

import psycopg
import pytest
from psycopg.rows import dict_row


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


def test_max_db_client_connections_local_override_global(bouncer):
    """Test that database level max_db_client_connections overrides server level max_db_client_connections."""
    test_db = "conn_limit_db"
    connect_args = {"dbname": test_db, "user": "muser1"}
    conns = [bouncer.conn(**connect_args) for _ in range(2)]
    dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
    db = next(db for db in dbs if db["name"] == test_db)
    assert db["current_client_connections"] == 2
    assert db["max_client_connections"] == 2
    with pytest.raises(psycopg.OperationalError, match=r"max_db_client_connections"):
        _ = bouncer.conn(**connect_args)
    with pytest.raises(psycopg.OperationalError, match=r"max_db_client_connections"):
        _ = bouncer.conn(**connect_args)

    for conn in conns:
        conn.close()


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "muser1"),
        ("pgbouncer", "pgbouncer"),
        ("pgbouncer", "muser1"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_db_client_connections_global_negative(
    bouncer, test_db: str, test_user: str
) -> None:
    """Negative test of server wide max_db_client_connections setting."""
    bouncer.admin("SET max_db_client_connections = 2")
    bouncer.admin("SET stats_users = 'muser1'")
    bouncer.admin("SET admin_users = 'pgbouncer'")

    connect_args = {"dbname": test_db, "user": test_user}
    conns = [bouncer.conn(**connect_args) for _ in range(2)]
    dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
    db = next(db for db in dbs if db["name"] == test_db)
    assert db["current_client_connections"] == 2 if test_db == "p0" else 3
    assert db["max_client_connections"] == 2

    if test_db == "pgbouncer" and test_user == "pgbouncer":
        _ = bouncer.conn(**connect_args)
    else:
        with pytest.raises(
            psycopg.OperationalError, match=r"max_db_client_connections"
        ):
            _ = bouncer.conn(**connect_args)

    for conn in conns:
        conn.close()


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "muser1"),
        ("pgbouncer", "pgbouncer"),
        ("pgbouncer", "muser1"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_db_client_connections_global_positive(
    bouncer, test_db: str, test_user: str
) -> None:
    """Positive test of server wide max_db_client_connections setting."""
    # with bouncer.run_with_config(config):
    bouncer.admin("SET max_db_client_connections = 2")
    bouncer.admin("SET stats_users = 'muser1'")
    bouncer.admin("SET admin_users = 'pgbouncer'")

    connect_args = {"dbname": test_db, "user": test_user}
    conn = bouncer.conn(**connect_args)
    # should still be allowed, since it's the last allowed connection
    dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
    db = next(db for db in dbs if db["name"] == test_db)
    assert db["current_client_connections"] == 1 if test_db == "p0" else 2
    assert db["max_client_connections"] == 2
    _ = bouncer.conn(**connect_args)
    conn.close()


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
    bouncer.admin("SET stats_users = 'muser1'")
    bouncer.admin("SET admin_users = 'pgbouncer'")

    connect_args = {"dbname": test_db, "user": test_user}
    [_conn_1, conn_2] = [bouncer.conn(**connect_args) for _ in range(2)]
    dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
    db = next(db for db in dbs if db["name"] == test_db)
    assert db["current_client_connections"] == 2 if test_db == "p0" else 3

    conn_2.close()
    dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
    db = next(db for db in dbs if db["name"] == test_db)
    assert db["current_client_connections"] == 1 if test_db == "p0" else 2


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("client_limit_db", "muser1"),
        ("client_limit_db_auth_passthrough", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_db_client_connections_negative(
    bouncer, test_db: str, test_user: str
) -> None:
    """Negative test of database specific max_db_client_connections setting."""
    connect_args = {"dbname": test_db, "user": test_user}
    # with bouncer.run_with_config(config):
    conns = [bouncer.conn(**connect_args) for _ in range(2)]
    dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
    db = next(db for db in dbs if db["name"] == test_db)
    assert db["current_client_connections"] == 2 if test_db == "p0" else 3
    assert db["max_client_connections"] == 2

    with pytest.raises(psycopg.OperationalError, match=r"max_db_client_connections"):
        bouncer.conn(**connect_args)

    for conn in conns:
        conn.close()


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("client_limit_db", "muser1"),
        ("client_limit_db_auth_passthrough", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_db_client_connections_positive(bouncer, test_db: str, test_user) -> None:
    """Positive test of database specific max_db_client_connections setting."""
    connect_args = {"dbname": test_db, "user": test_user}
    # with bouncer.run_with_config(config):
    conn = bouncer.conn(**connect_args)
    # should still be allowed, since it's the last allowed connection
    dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)
    db = next(db for db in dbs if db["name"] == test_db)
    assert db["current_client_connections"] == 1 if test_db == "p0" else 2
    assert db["max_client_connections"] == 2
    _ = bouncer.conn(**connect_args)
    conn.close()


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


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "maxedout3"),
        ("pgbouncer", "maxedout3"),
        ("pgbouncer", "maxedout2"),
        ("pauthz", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_user_client_connections_local_override_global(
    bouncer, test_db: str, test_user: str
) -> None:
    """Test that user level overrides global connection limit.

    1. Set global client connection limit
    2. Grab user data from `SHOW USERS` for user with max_user_client_connections set
    3. Validate that the user level max_user_client_connections is returned

    Tests 4 users: normal, admin, stats, and auth pass through
    """
    bouncer.admin("set max_user_client_connections=1")
    bouncer.admin("set admin_users='maxedout3,pgbouncer'")
    bouncer.admin("set stats_users=maxedout2")

    connect_args = {"dbname": test_db, "user": test_user}

    conn_1 = bouncer.conn(**connect_args)
    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["max_user_client_connections"] == 2
    assert user["current_client_connections"] == 1

    bouncer.conn(**connect_args)
    conn_1.close()


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "maxedout4"),
        ("pgbouncer", "maxedout4"),
        ("pgbouncer", "maxedout5"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_user_client_connections_global_positive(
    bouncer, test_db: str, test_user: str
) -> None:
    """Positive test for global max_user_client_connections setting."""
    bouncer.admin("SET max_user_client_connections=2")
    bouncer.admin("SET admin_users='maxedout4,pgbouncer'")
    bouncer.admin("SET stats_users='maxedout5'")

    connect_args = {"dbname": test_db, "user": test_user}
    conn_1 = bouncer.conn(**connect_args)
    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["max_user_client_connections"] == 2
    assert user["current_client_connections"] == 1
    # should still be allowed, since it's the last allowed connection
    bouncer.conn(**connect_args)
    conn_1.close()


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "maxedout4"),
        ("pgbouncer", "maxedout4"),
        ("pgbouncer", "maxedout5"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_user_client_connections_global_negative(
    bouncer, test_db: str, test_user: str
) -> None:
    """Negative test for max_user_client_connections setting.

    Test that default user level connection limit correctly rejects connection after
    2 users are connected. Also checks that user counts are correctly reflected in
    SHOW USERS stats command.
    Test covers admin db and real db
    """
    bouncer.admin("SET max_user_client_connections=2")
    bouncer.admin("SET admin_users='maxedout4,pgbouncer'")
    bouncer.admin("SET stats_users='maxedout5'")

    connect_args = {"dbname": test_db, "user": test_user}
    conns = [bouncer.conn(**connect_args) for _ in range(2)]
    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["max_user_client_connections"] == 2
    assert user["current_client_connections"] == 2

    # Make sure error is correctly 2 times sequentially
    for _ in range(2):
        if test_db == "pgbouncer" and test_user == "maxedout4":
            bouncer.conn(**connect_args)
        else:
            with pytest.raises(
                psycopg.OperationalError, match=r"max_user_client_connections"
            ):
                bouncer.conn(**connect_args)

    for conn in conns:
        conn.close()


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "maxedout3"),
        ("pgbouncer", "maxedout3"),
        ("pgbouncer", "maxedout2"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_user_client_connections_positive(
    bouncer, test_db: str, test_user: str
) -> None:
    """Positive test of user level max_user_client_connections setting.

    Test that user level connection limits allow users to connect up to the limit level.
    Also test that SHOW USERS stats correctly reflect this number.
    """
    bouncer.admin("SET max_user_client_connections=2")
    bouncer.admin("SET admin_users='maxedout2,pgbouncer'")
    bouncer.admin("SET stats_users='maxedout3'")
    connect_args = {"dbname": test_db, "user": test_user}
    conn_1 = bouncer.conn(**connect_args)
    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["max_user_client_connections"] == 2
    assert user["current_client_connections"] == 1

    # should still be allowed, since it's the last allowed connection
    conn_2 = bouncer.conn(**connect_args)

    for conn in [conn_1, conn_2]:
        conn.close()


@pytest.mark.parametrize(
    ("test_db", "test_user"),
    [
        ("p0", "maxedout3"),
        ("pgbouncer", "maxedout3"),
        ("pgbouncer", "maxedout2"),
        ("authdb", "pswcheck_not_in_auth_file"),
    ],
)
def test_max_user_client_connections_negative(
    bouncer, test_db: str, test_user: str
) -> None:
    """Negative test of user level max_user_client_connections setting.

    Test that user level connection limit correctly rejects connection after
    2 users are connected. Also checks that user counts are correctly reflected in
    SHOW USERS stats command.
    Test covers admin db and real db
    """
    bouncer.admin("SET max_user_client_connections=2")
    bouncer.admin("SET admin_users='maxedout2,pgbouncer'")
    bouncer.admin("SET stats_users='maxedout3'")
    connect_args = {"dbname": test_db, "user": test_user}
    conns = [bouncer.conn(**connect_args) for _ in range(2)]
    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["max_user_client_connections"] == 2
    assert user["current_client_connections"] == 2

    if test_db == "pgbouncer" and test_user == "maxedout2":
        bouncer.conn(**connect_args)
    else:
        with pytest.raises(
            psycopg.OperationalError, match=r"max_user_client_connections"
        ):
            bouncer.conn(**connect_args)

    for conn in conns:
        conn.close()


def test_user_client_count_db_connect_fail(pg, bouncer) -> None:
    test_user = "maxedout3"
    test_dbname = "user_passthrough"

    pg.nossl_access(dbname="p0", auth_type="reject", user=test_user)
    pg.ssl_access(dbname="p0", auth_type="reject", user=test_user)
    pg.reload()

    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["current_client_connections"] == 0

    connect_args = {"dbname": test_dbname, "user": test_user}
    with pytest.raises(
        psycopg.OperationalError, match="pg_hba.conf rejects connection"
    ):
        _ = bouncer.conn(**connect_args)

    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["current_client_connections"] == 0


def test_user_client_count_db_connect_fail_2(bouncer) -> None:
    test_user = "pswcheck_not_in_auth_file"
    test_dbname = "user_passthrough"

    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["current_client_connections"] == 0

    connect_args = {"dbname": test_dbname, "user": test_user}
    with pytest.raises(psycopg.OperationalError, match="authentication failed"):
        _ = bouncer.conn(**connect_args)

    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    user = next(user for user in users if user["name"] == test_user)
    assert user["current_client_connections"] == 0


def test_user_client_count_db_connect_fail_3(bouncer) -> None:
    test_user = "non_existent_user"
    test_dbname = "user_passthrough"

    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    assert len([user for user in users if user["name"] == test_user]) == 0

    connect_args = {"dbname": test_dbname, "user": test_user}
    with pytest.raises(psycopg.OperationalError, match="authentication failed"):
        _ = bouncer.conn(**connect_args)

    users = bouncer.admin("SHOW USERS", row_factory=dict_row)
    # We don't expect non-existent users which cannot authentiticate to show up
    # in the stats at all. This would just pollute the stats output with people
    # making typos or attackers trying random user accounts.
    assert len([user for user in users if user["name"] == test_user]) == 0


async def test_reload_resets_removed_user_settings(pg, bouncer):
    """Deleting a [users] entry and reloading takes its settings away with it."""
    bouncer.write_ini(
        "[users]\nmaxedout4 = pool_size=1 pool_mode=transaction"
        " max_user_client_connections=4"
    )
    bouncer.admin("reload")

    users = {u["name"]: u for u in bouncer.admin("SHOW USERS", row_factory=dict_row)}
    assert users["maxedout4"]["pool_size"] == "        1"
    assert users["maxedout4"]["pool_mode"] == "transaction"
    assert users["maxedout4"]["max_user_client_connections"] == 4

    # p0a has a pool_size of two, and the user's one is what holds this pool below
    # it. The clients query at the same time and for long enough to overlap on a
    # loaded machine, or the pool has no reason to open a second connection and
    # this would pass with no cap in place at all.
    await bouncer.asleep(1, dbname="p0a", user="maxedout4", times=4)
    assert pg.connection_count(dbname="p0", users=("maxedout4",)) == 1

    bouncer.reset_ini()
    bouncer.admin("reload")

    users = {u["name"]: u for u in bouncer.admin("SHOW USERS", row_factory=dict_row)}
    assert users["maxedout4"]["pool_size"] == ""
    assert users["maxedout4"]["pool_mode"] is None
    # zero is what max_user_client_connections reports once nothing sets it, since
    # the [pgbouncer] default is what a user without one of its own falls back to.
    assert users["maxedout4"]["max_user_client_connections"] == 0
    await bouncer.asleep(1, dbname="p0a", user="maxedout4", times=4)
    assert pg.connection_count(dbname="p0", users=("maxedout4",)) == 2


def break_ini_before_users(bouncer):
    """Put an unparsable line in the ini's first section, ahead of [users]

    cf_load_file() gives up at the first bad line, so nothing after this one is
    read: not the [users] section, and not the [pgbouncer] one either, whose
    settings therefore keep the values the last readable file gave them.
    """
    with bouncer.ini_path.open() as f:
        broken = f.read().replace(
            "[databases]",
            "[databases]\nbroken_db = port=6666 host=127.0.0.1 dbname=p0 nonsense=1",
            1,
        )
    with bouncer.ini_path.open("w") as f:
        f.write(broken)

    with pytest.raises(
        psycopg.errors.ConfigFileError,
        match=r"RELOAD failed, see logs for additional details",
    ):
        bouncer.admin("RELOAD")


async def test_reload_error_before_users_keeps_user_settings(pg, bouncer):
    """A reload that gives up before [users] leaves those settings being enforced.

    Only the section the failed reload never reached is covered, and that is all
    that is guaranteed: parse_user() writes straight into the live user, so an
    entry the reader did get to before the bad line is applied even though the
    reload as a whole fails.
    """
    # maxedout5 carries the timeout on its own, since a query_timeout on the user
    # whose pool_size is one would fall on the clients waiting behind it as well.
    bouncer.write_ini(
        "[users]\nmaxedout4 = pool_size=1 reserve_pool_size=2 max_user_connections=3"
        "\nmaxedout5 = query_timeout=2"
    )
    bouncer.admin("reload")

    users = {u["name"]: u for u in bouncer.admin("SHOW USERS", row_factory=dict_row)}
    assert users["maxedout4"]["pool_size"] == "        1"
    assert users["maxedout4"]["reserve_pool_size"] == "        2"
    assert users["maxedout4"]["max_user_connections"] == 3

    break_ini_before_users(bouncer)

    users = {u["name"]: u for u in bouncer.admin("SHOW USERS", row_factory=dict_row)}
    assert users["maxedout4"]["pool_size"] == "        1"
    assert users["maxedout4"]["reserve_pool_size"] == "        2"
    assert users["maxedout4"]["max_user_connections"] == 3

    # and the settings are still the ones being applied, not just the ones being
    # reported: p0a's pool_size is two, so a pool that is still capped at one is
    # the user's setting doing it. The clients query at the same time and for long
    # enough to overlap, or the pool has no reason to open a second connection.
    await bouncer.asleep(1, dbname="p0a", user="maxedout4", times=4)
    assert pg.connection_count(dbname="p0", users=("maxedout4",)) == 1

    # The timeouts need more than the field kept: whether any user sets one at all
    # is cached in a flag that load_config() clears before reading the file, so a
    # failed load has to put that back too or nothing looks at the field again.
    with (
        bouncer.log_contains(r"query timeout"),
        pytest.raises(
            psycopg.OperationalError,
            match=r"query timeout|server closed the connection unexpectedly",
        ),
    ):
        bouncer.sleep(8, dbname="p0a", user="maxedout5")

    # a reload that can be read still defaults a user its [users] section no longer
    # mentions.
    bouncer.reset_ini()
    bouncer.admin("reload")

    users = {u["name"]: u for u in bouncer.admin("SHOW USERS", row_factory=dict_row)}
    assert users["maxedout4"]["pool_size"] == ""
    assert users["maxedout4"]["reserve_pool_size"] == ""
    assert users["maxedout4"]["max_user_connections"] == 0


def test_reload_error_keeps_enforcing_user_client_idle_timeout(bouncer):
    """A failed reload goes on enforcing a per-user client_idle_timeout.

    Whether any user sets one is cached in a flag that load_config() clears before
    it starts reading, so a reload that fails has to put the flag back or the
    janitor stops looking at the field it did keep.  Nothing sets a global
    client_idle_timeout here, so the user's flag is the only thing keeping the
    janitor looking at idle clients at all.
    """
    bouncer.write_ini("[users]\nmaxedout5 = client_idle_timeout=2")
    bouncer.admin("reload")

    break_ini_before_users(bouncer)

    with bouncer.cur(dbname="p0a", user="maxedout5") as cur:
        cur.execute("SELECT 1")
        with bouncer.log_contains(r"client_idle_timeout"):
            time.sleep(3)
            with pytest.raises(
                psycopg.OperationalError,
                match=r"client_idle_timeout|Software caused connection abort"
                r"|server closed the connection unexpectedly",
            ):
                cur.execute("SELECT 1")


async def test_reload_error_keeps_enforcing_database_query_wait_timeout(bouncer):
    """A failed reload goes on enforcing a per-database query_wait_timeout.

    There is a flag for the databases as well, and the global query_wait_timeout is
    set to zero here so that it is the only thing keeping the janitor looking at
    waiting clients: the flag for the users opens the same gate, so no user may set
    a timeout in this test either.
    """
    waitqueue = (
        f"[databases]\nwaitqueue = host={bouncer.pg.host} port={bouncer.pg.port}"
        " dbname=p0 pool_size=1 reserve_pool_size=0 query_wait_timeout=2"
    )
    bouncer.write_ini("query_wait_timeout = 0\n" + waitqueue)
    bouncer.admin("reload")

    break_ini_before_users(bouncer)

    blocker = bouncer.asleep(6, dbname="waitqueue", user="maxedout5")
    await asyncio.sleep(1)
    with pytest.raises(psycopg.OperationalError, match=r"query_wait_timeout"):
        bouncer.sleep(1, dbname="waitqueue", user="maxedout5")
    await blocker


def test_reload_resets_removed_user_query_timeout(bouncer):
    """Deleting a [users] entry stops its query_timeout being enforced.

    maxedout4 keeps a query_timeout of its own so that the janitor goes on looking
    at the per-user timeouts at all: it skips the whole sweep when no user sets
    one, which would let this pass with maxedout5's field still in place.
    """
    bouncer.write_ini(
        "[users]\nmaxedout5 = query_timeout=2\nmaxedout4 = query_timeout=60"
    )
    bouncer.admin("reload")

    with (
        bouncer.log_contains(r"query timeout"),
        pytest.raises(
            psycopg.OperationalError,
            match=r"query timeout|server closed the connection unexpectedly",
        ),
    ):
        bouncer.sleep(8, dbname="p0a", user="maxedout5")

    bouncer.reset_ini()
    bouncer.write_ini("[users]\nmaxedout4 = query_timeout=60")
    bouncer.admin("reload")

    bouncer.sleep(4, dbname="p0a", user="maxedout5")


async def test_reload_resets_removed_user_query_wait_timeout(bouncer):
    """Deleting a [users] entry stops its query_wait_timeout overriding the global.

    This one is the other way round: the user's entry raises the timeout rather
    than lowering it, so that removing it has to clear both the field and the flag
    that says the user has one at all -- a flag left set with the field back at
    zero would stop the global timeout being applied instead.  The global timeout
    is appended to the [pgbouncer] section test.ini ends with, and the pool_size of
    one that makes a client wait at all is the database's, so that deleting the
    [users] entry does not take that away too.
    """
    waitqueue = (
        f"[databases]\nwaitqueue = host={bouncer.pg.host} port={bouncer.pg.port}"
        " dbname=p0 pool_size=1 reserve_pool_size=0"
    )
    bouncer.write_ini(
        "query_wait_timeout = 2\n"
        + waitqueue
        + "\n[users]\nmaxedout5 = query_wait_timeout=60"
    )
    bouncer.admin("reload")

    # the client queued behind the one server connection waits the three seconds
    # out instead of being killed at two, because the user's sixty is what counts.
    blocker = bouncer.asleep(4, dbname="waitqueue", user="maxedout5")
    await asyncio.sleep(1)
    bouncer.sleep(1, dbname="waitqueue", user="maxedout5")
    await blocker

    bouncer.reset_ini()
    bouncer.write_ini("query_wait_timeout = 2\n" + waitqueue)
    bouncer.admin("reload")

    blocker = bouncer.asleep(6, dbname="waitqueue", user="maxedout5")
    await asyncio.sleep(1)
    with pytest.raises(psycopg.OperationalError, match=r"query_wait_timeout"):
        bouncer.sleep(1, dbname="waitqueue", user="maxedout5")
    await blocker


def test_reload_resets_removed_user_client_idle_timeout(bouncer):
    """Deleting a [users] entry stops its client_idle_timeout being enforced.

    The global client_idle_timeout, which is appended to the [pgbouncer] section
    test.ini ends with, is what keeps the janitor looking at idle clients here.  A
    second user with a timeout of its own cannot do that job the way it can for
    query_timeout: without a global timeout the janitor takes the zero a user
    without one of its own has as expired at once, and disconnects it immediately.
    """
    bouncer.write_ini(
        "client_idle_timeout = 60\n[users]\nmaxedout5 = client_idle_timeout=2"
    )
    bouncer.admin("reload")

    with bouncer.cur(dbname="p0a", user="maxedout5") as cur:
        cur.execute("SELECT 1")
        with bouncer.log_contains(r"client_idle_timeout"):
            time.sleep(3)
            with pytest.raises(
                psycopg.OperationalError,
                match=r"client_idle_timeout|Software caused connection abort"
                r"|server closed the connection unexpectedly",
            ):
                cur.execute("SELECT 1")

    bouncer.reset_ini()
    bouncer.write_ini("client_idle_timeout = 60")
    bouncer.admin("reload")

    with bouncer.cur(dbname="p0a", user="maxedout5") as cur:
        cur.execute("SELECT 1")
        time.sleep(3)
        cur.execute("SELECT 1")


def test_reload_resets_removed_user_transaction_timeout(bouncer):
    """Deleting a [users] entry stops its transaction_timeout being enforced.

    The pool_mode and the global timeout are appended to the [pgbouncer] section
    test.ini ends with: transactions need a pool mode that allows them, and the
    global timeout is what keeps the janitor looking once the user's is gone.
    """
    bouncer.write_ini(
        "pool_mode = transaction\ntransaction_timeout = 60"
        "\n[users]\nmaxedout5 = transaction_timeout=2"
    )
    bouncer.admin("reload")

    with (
        bouncer.log_contains(r"transaction timeout"),
        pytest.raises(
            psycopg.OperationalError,
            match=r"transaction timeout|server closed the connection unexpectedly",
        ),
        bouncer.cur(dbname="p0a", user="maxedout5") as cur,
    ):
        cur.execute("BEGIN")
        cur.execute("SELECT pg_sleep(4)")
        cur.execute("SELECT 1")

    bouncer.reset_ini()
    bouncer.write_ini("pool_mode = transaction\ntransaction_timeout = 60")
    bouncer.admin("reload")

    with bouncer.cur(dbname="p0a", user="maxedout5") as cur:
        cur.execute("BEGIN")
        cur.execute("SELECT pg_sleep(4)")
        cur.execute("SELECT 1")
        cur.execute("COMMIT")


def test_reload_resets_removed_user_idle_transaction_timeout(bouncer):
    """Deleting a [users] entry stops its idle_transaction_timeout being enforced."""
    bouncer.write_ini(
        "pool_mode = transaction\nidle_transaction_timeout = 60"
        "\n[users]\nmaxedout5 = idle_transaction_timeout=2"
    )
    bouncer.admin("reload")

    with (
        bouncer.log_contains(r"idle transaction timeout"),
        pytest.raises(
            psycopg.OperationalError,
            match=r"idle transaction timeout|Software caused connection abort|server closed the connection unexpectedly",
        ),
        bouncer.cur(dbname="p0a", user="maxedout5") as cur,
    ):
        cur.execute("BEGIN")
        cur.execute("SELECT 1")
        time.sleep(4)
        cur.execute("SELECT 1")

    bouncer.reset_ini()
    bouncer.write_ini("pool_mode = transaction\nidle_transaction_timeout = 60")
    bouncer.admin("reload")

    with bouncer.cur(dbname="p0a", user="maxedout5") as cur:
        cur.execute("BEGIN")
        cur.execute("SELECT 1")
        time.sleep(4)
        cur.execute("SELECT 1")
        cur.execute("COMMIT")


def test_min_pool_size_with_lower_max_user_connections(bouncer):
    # The p0x in test.init has min_pool_size set to 5. This should make
    # the PgBouncer try to create a pool for maxedout2 user of size 5 after a
    # client connects to the PgBouncer. However maxedout2 user has
    # max_user_connections set to 2, so the final pool size should be only 2.

    # Running a query for sufficient time for us to reach the final
    # connection count in the pool and detect any evictions.
    with (
        bouncer.log_contains(r"new connection to server \(from", times=2),
        bouncer.log_contains("closing because: evicted", times=0),
    ):
        bouncer.sleep(2, dbname="p0x", user="maxedout2")


def test_min_pool_size_with_lower_max_db_connections(bouncer):
    # The p0x in test.init has min_pool_size set to 5. This should make
    # the PgBouncer try to create a pool for puser1 user of size 5 after a client
    # connects to the PgBouncer. However the db also has max_db_connections set
    # to 2, so the final pool size should be only 2.

    # Running a query for sufficient time for us to reach the final
    # connection count in the pool and detect any evictions.
    with (
        bouncer.log_contains(r"new connection to server \(from", times=2),
        bouncer.log_contains("closing because: evicted", times=0),
    ):
        bouncer.sleep(2, dbname="p0y", user="puser1")


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


async def test_user_reserve_pool_size(pg, bouncer):
    bouncer.admin("set reserve_pool_timeout = 2")

    # Disable tls to get more consistent timings
    bouncer.admin("set server_tls_sslmode = disable")

    with bouncer.log_contains("taking connection from reserve_pool", times=2):
        # respoolsize1 user has a pool_size of 1 and reserve_pool_size of 2
        # this means 1 connection should happen immediately while 2 out of
        # the 3 remaining connections happen after reserve_pool_timeout
        result = bouncer.asleep(10, dbname="p0a", user="respoolsize1", times=4)
        await asyncio.sleep(1)
        assert pg.connection_count(dbname="p0", users=("respoolsize1",)) == 1
        await asyncio.sleep(8)
        assert pg.connection_count(dbname="p0", users=("respoolsize1",)) == 3
        await result


async def test_database_reserve_pool_size(pg, bouncer):
    bouncer.admin("set reserve_pool_timeout = 2")

    # Disable tls to get more consistent timings
    bouncer.admin("set server_tls_sslmode = disable")

    with bouncer.log_contains("taking connection from reserve_pool", times=2):
        # p0 db has a pool_size of 2 and reserve_pool_size of 2
        # this means 2 connections should happen immediately while 2 out of
        # the 3 remaining connections happen after reserve_pool_timeout
        result = bouncer.asleep(10, dbname="p0", user="bouncer", times=5)
        await asyncio.sleep(1)
        assert pg.connection_count(dbname="p0", users=("bouncer",)) == 2
        await asyncio.sleep(8)
        assert pg.connection_count(dbname="p0", users=("bouncer",)) == 4
        await result


async def test_database_reserve_pool_size_old_param(pg, bouncer):
    bouncer.admin("set reserve_pool_timeout = 2")

    # Disable tls to get more consistent timings
    bouncer.admin("set server_tls_sslmode = disable")

    with bouncer.log_contains("taking connection from reserve_pool", times=2):
        # p0a db has a pool_size of 2 and reserve_pool of 2
        # this means 2 connections should happen immediately while 2 out of
        # the 3 remaining connections happen after reserve_pool_timeout
        result = bouncer.asleep(10, dbname="p0a", user="bouncer", times=5)
        await asyncio.sleep(1)
        assert pg.connection_count(dbname="p0", users=("bouncer",)) == 2
        await asyncio.sleep(8)
        assert pg.connection_count(dbname="p0", users=("bouncer",)) == 4
        await result


async def test_max_db_connections(pg, bouncer):
    # some users, doesn't matter which ones
    users = ["muser1", "muser2", "puser1", "puser2", "postgres"]

    # p2 has max_db_connections=4
    await asyncio.gather(
        *[bouncer.asleep(0.5, dbname="p2", user=u, times=2) for u in users]
    )

    # p2 in PgBouncer maps to p0 in Postgres
    assert pg.connection_count("p0", users=users) == 4


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
