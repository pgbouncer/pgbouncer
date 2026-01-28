import asyncio
import re
import threading
import time

import psycopg
import pytest

from .utils import (
    HAVE_IPV6_LOCALHOST,
    LINUX,
    PG_MAJOR_VERSION,
    PG_SUPPORTS_SCRAM,
    PKT_BUF_SIZE,
    USE_UNIX_SOCKETS,
    WINDOWS,
)


@pytest.mark.parametrize(
    "test_auth_type", ["trust"] if WINDOWS else ["trust", "scram-sha-256"]
)
@pytest.mark.skipif("not PG_SUPPORTS_SCRAM")
def test_scram_server(bouncer, test_auth_type):
    """
    Test that query_wait_notify setting plays nicely with scram-sha-256 authentication.

    Please note that this test does not work when using scram-sha-256 test_auth_type on
    windows. This is because windows does not allow socket connections which would allow
    connection to the admin console to reload without a password.
    """
    config = f"""
    [databases]
    p6 = port=6666 host=127.0.0.1 dbname=p6 user=scramuser1 password=foo max_db_connections=0
    postgres = host={bouncer.pg.host} port={bouncer.pg.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    admin_users = pgbouncer
    auth_type = {test_auth_type}
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    pool_mode = session
    query_wait_notify = 1

    [users]
    puser1 = max_user_connections = 1
    """
    with bouncer.run_with_config(config):
        # good password from ini
        with pytest.raises(psycopg.errors.ConnectionTimeout):
            if test_auth_type == "trust":
                bouncer.test(dbname="p6")
            else:
                bouncer.test(dbname="p6", password="foo", user="scramuser1")


async def test_notify_queue_negative(bouncer):
    """
    Test that wait notification will not occur when query_wait_notify
    is set to longer than the client will be waiting in the queue for.
    """
    config = f"""
    [databases]
    postgres = host={bouncer.pg.host} port={bouncer.pg.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    admin_users = pgbouncer
    auth_type = trust
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    pool_mode = statement
    query_wait_notify = 8

    [users]
    puser1 = max_user_connections=1
    """
    notices_received = []

    def log_notice(diag):
        notices_received.append(diag.message_primary)

    with bouncer.run_with_config(config):

        sleep_future = bouncer.asql(
            "SELECT pg_sleep(6)", dbname="postgres", user="puser1"
        )
        _, sleep_future = await asyncio.wait([sleep_future], timeout=1)

        conn_2: psycopg.AsyncConnection = await bouncer.aconn(
            dbname="postgres", user="puser1"
        )
        conn_2.add_notice_handler(log_notice)
        curr = await conn_2.execute("select 1;")
        await curr.fetchall()

        assert len(notices_received) == 0

        sleep_future = bouncer.asql(
            "SELECT pg_sleep(6)", dbname="postgres", user="puser1"
        )
        _, sleep_future = await asyncio.wait([sleep_future], timeout=1)

        curr = await conn_2.execute("select 1;")
        await curr.fetchall()
        assert len(notices_received) == 0

        await conn_2.close()


async def test_notify_queue(bouncer):
    """
    Test that client is notified when they are waiting for longer
    than query_wait_notify seconds. Also tests that the notification
    is correctly sent if they are waiting in a second time during the
    same connection.
    """
    config = f"""
    [databases]
    postgres = host={bouncer.pg.host} port={bouncer.pg.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    admin_users = pgbouncer
    auth_type = trust
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    pool_mode = statement
    query_wait_notify = 2

    [users]
    puser1 = max_user_connections=1
    """
    notices_received = []

    def log_notice(diag):
        notices_received.append(diag.message_primary)

    with bouncer.run_with_config(config):

        sleep_future = bouncer.asql(
            "SELECT pg_sleep(6)", dbname="postgres", user="puser1"
        )
        _, sleep_future = await asyncio.wait([sleep_future], timeout=1)

        conn_2: psycopg.AsyncConnection = await bouncer.aconn(
            dbname="postgres", user="puser1"
        )
        conn_2.add_notice_handler(log_notice)
        curr = await conn_2.execute("select 1;")
        await curr.fetchall()

        assert len(notices_received) == 1
        expected_message = (
            "No server connection available in postgres backend, client being queued"
        )
        assert expected_message == notices_received[0]

        sleep_future = bouncer.asql(
            "SELECT pg_sleep(6)", dbname="postgres", user="puser1"
        )
        _, sleep_future = await asyncio.wait([sleep_future], timeout=1)

        curr = await conn_2.execute("select 1;")
        await curr.fetchall()
        assert len(notices_received) == 2
        assert expected_message == notices_received[1]

        await conn_2.close()


@pytest.mark.skipif("not LINUX", reason="socat proxy only available on linux")
def test_server_check_query_default_negative(pg, bouncer, proxy):
    """
    Test that default server check query correctly spots bad connection.

    Bad connection is created by simulating a network failure by proxying
    postgres behind socat. The socat process is killed right before the
    postgres process is terminated, after this socat is started again.

    The expectation is that the health check query will not show up
    in the postgres log, a new connection with a new pid will be granted
    to the client without any exception being raised.
    """
    config = f"""
    [databases]
    postgres = host={proxy.host} port={proxy.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    auth_type = trust
    admin_users = pgbouncer
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    auth_dbname = postgres
    pool_mode = transaction
    server_check_delay = 0
    """
    pg.configure(config="log_statement = 'all'")
    pg.reload()

    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            pid = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        proxy.stop()
        pg.sql(f"SELECT pg_terminate_backend({pid});")
        proxy.start()

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            with pg.log_contains(" LOG:  statement: \n", times=0):
                new_pid = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

    assert new_pid != pid
    pg.configure(config="log_statement = 'none'")


@pytest.mark.skipif("not LINUX", reason="socat proxy only available on linux")
def test_server_check_query_negative(pg, bouncer, proxy):
    """
    Test that a custom server check query correctly spots bad connection.

    Bad connection is created by simulating a network failure by proxying
    postgres behind socat. The socat process is killed right before the
    postgres process is terminated, after this socat is started again.

    The expectation is that the health check query will not show up
    in the postgres log, a new connection with a new pid will be granted
    to the client without any exception being raised.
    """
    config = f"""
    [databases]
    postgres = host={proxy.host} port={proxy.port} pool_size=1

    [pgbouncer]
    listen_addr = {bouncer.host}
    auth_type = trust
    admin_users = pgbouncer
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    auth_dbname = postgres
    pool_mode = transaction
    server_check_query = SELECT 2
    server_check_delay = 0
    """
    pg.configure(config="log_statement = 'all'")
    pg.reload()

    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            pid = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        proxy.stop()
        pg.sql(f"SELECT pg_terminate_backend({pid});")
        proxy.start()

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            with pg.log_contains(" LOG:  statement: SELECT 2\n", times=0):
                new_pid = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

    assert new_pid != pid
    pg.configure(config="log_statement = 'none'")


def test_server_check_query_default(
    pg,
    bouncer,
):
    """
    Test that a default server check query correctly checks for a bad connection.

    In this case there will be no bad connection.

    The expectation is that the health check query will show up
    in the postgres log once, the previously used postgres process will be
    provided to the user as validated by the pid.
    """
    config = f"""
    [databases]
    postgres = host={pg.host} port={pg.port}

    [pgbouncer]
    listen_addr = {bouncer.host}
    auth_type = trust
    admin_users = pgbouncer
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    auth_dbname = postgres
    pool_mode = transaction
    server_check_delay = 0
    """
    pg.configure(config="log_statement = 'all'")
    pg.reload()

    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            pid = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            with pg.log_contains(" LOG:  statement: \n", times=1):
                new_pid = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

    assert new_pid == pid
    pg.configure(config="log_statement = 'none'")


def test_server_check_query(pg, bouncer):
    """
    Test that a custom server check query correctly checks for a bad connection.

    In this case there will be no bad connection.

    The expectation is that the health check query will show up
    in the postgres log once, the previously used postgres process will be
    provided to the user as validated by the pid.
    """
    config = f"""
    [databases]
    postgres = host={bouncer.pg.host} port={bouncer.pg.port} pool_size=1

    [pgbouncer]
    listen_addr = {bouncer.host}
    auth_type = trust
    admin_users = pgbouncer
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    auth_dbname = postgres
    pool_mode = transaction
    server_check_query = SELECT 2
    server_check_delay = 0
    """
    pg.configure(config="log_statement = 'all'")
    pg.reload()

    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            pid = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            with pg.log_contains(" LOG:  statement: SELECT 2\n", times=1):
                new_pid = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

    assert new_pid == pid
    pg.configure(config="log_statement = 'none'")


def test_connect_query(bouncer):
    # The p8 database definition in test.ini has some GUC settings
    # in connect_query.  Check that they get set.  (The particular
    # settings don't matter; just use some that are easy to set
    # and read.)

    assert bouncer.sql_value("show enable_seqscan", dbname="p8") == "off"
    assert bouncer.sql_value("show enable_nestloop", dbname="p8") == "off"


def test_fast_close(bouncer):
    with bouncer.cur(dbname="p3") as cur:
        cur.execute("select 1")
        bouncer.admin("set server_fast_close = 1")
        with bouncer.log_contains(r"closing because: database configuration changed"):
            bouncer.admin("reconnect p3")
            time.sleep(1)

            with pytest.raises(
                psycopg.OperationalError,
                match=r"database configuration changed|server closed the connection unexpectedly|Software caused connection abort",
            ):
                cur.execute("select 1")


def test_track_extra_parameters(bouncer):
    # test.ini has track_extra_parameters set to a list of Postgres
    # parameters. Test that the parameters in the list in addition to the
    # default hardcoded list of parameters are cached per client.
    bouncer.admin(f"set pool_mode=transaction")

    test_set = {
        "intervalstyle": ["sql_standard", "postgres"],
        "standard_conforming_strings": ["ON", "OFF"],
        "timezone": ["'Europe/Amsterdam'", "'Europe/Rome'"],
        "datestyle": ["PostgreSQL,European", "ISO,US"],
        "application_name": ["client1", "client2"],
    }

    if not WINDOWS:
        test_set["client_encoding"] = ["LATIN1", "LATIN5"]

    test_expected = {
        "intervalstyle": ["sql_standard", "postgres"],
        "standard_conforming_strings": ["on", "off"],
        "timezone": ["Europe/Amsterdam", "Europe/Rome"],
        "datestyle": ["Postgres, DMY", "ISO, MDY"],
        "application_name": ["client1", "client2"],
    }

    if not WINDOWS:
        test_expected["client_encoding"] = ["LATIN1", "LATIN5"]

    with bouncer.cur(dbname="p1") as cur1:
        with bouncer.cur(dbname="p1") as cur2:
            for key in test_set:
                stmt1 = "SET " + key + " TO " + test_set[key][0]
                stmt2 = "SET " + key + " TO " + test_set[key][1]
                cur1.execute(stmt1)
                cur2.execute(stmt2)

                stmt = "SHOW " + key
                cur1.execute(stmt)
                cur2.execute(stmt)

                result1 = cur1.fetchone()
                assert result1[0] == test_expected[key][0]

                result2 = cur2.fetchone()
                assert result2[0] == test_expected[key][1]


async def test_wait_close(bouncer):
    with bouncer.cur(dbname="p3") as cur:
        cur.execute("select 1")
        await bouncer.aadmin("reconnect p3")
        wait_close_task = bouncer.aadmin("wait_close p3")

        # We wait for 1 second to show that wait_close continues unless the
        # connection is closed.
        done, pending = await asyncio.wait([wait_close_task], timeout=1)
        assert done == set()
        assert pending == {wait_close_task}
    await wait_close_task


def test_auto_database(bouncer):
    with bouncer.ini_path.open() as f:
        original = f.read()
    with bouncer.ini_path.open("w") as f:
        # uncomment the auto-database line
        f.write(re.sub(r"^;\*", "*", original, flags=re.MULTILINE))

    bouncer.admin("reload")
    with bouncer.log_contains(r"registered new auto-database"):
        # p7 is not defined in test.ini
        bouncer.test(dbname="p7")


# This test checks database specifications with host lists.  The way
# we test this here is to have a host list containing an IPv4 and an
# IPv6 representation of localhost, and then we check the log that
# both connections were made.  Some CI environments don't have IPv6
# localhost configured.  Therefore, this test is skipped by default
# and needs to be enabled explicitly by setting HAVE_IPV6_LOCALHOST to
# non-empty.
@pytest.mark.skipif("not HAVE_IPV6_LOCALHOST")
async def test_host_list(bouncer):
    with bouncer.log_contains(r"new connection to server \(from 127.0.0.1", times=1):
        with bouncer.log_contains(r"new connection to server \(from \[::1\]", times=1):
            await bouncer.asleep(1, dbname="hostlist1", times=2)


# This is the same test as above, except it doesn't use any IPv6
# addresses.  So we can't actually tell apart that two separate
# connections are made.  But the test is useful to get some test
# coverage (valgrind etc.) of the host list code on systems without
# IPv6 enabled.
async def test_host_list_dummy(bouncer):
    with bouncer.log_contains(r"new connection to server \(from 127.0.0.1", times=2):
        await bouncer.asleep(1, dbname="hostlist2", times=2)


def test_options_startup_param(bouncer):
    assert (
        bouncer.sql_value("SHOW datestyle", options="  -c    datestyle=German,\\ YMD")
        == "German, YMD"
    )

    assert (
        bouncer.sql_value(
            "SHOW datestyle",
            options="-c timezone=Europe/Lisbon  -c    datestyle=German,\\ YMD",
        )
        == "German, YMD"
    )

    assert (
        bouncer.sql_value(
            "SHOW timezone",
            options="-c timezone=Europe/Lisbon  -c    datestyle=German,\\ YMD",
        )
        == "Europe/Lisbon"
    )

    assert (
        bouncer.sql_value(
            "SHOW timezone",
            options="-ctimezone=Europe/Lisbon  -cdatestyle=German,\\ YMD",
        )
        == "Europe/Lisbon"
    )

    assert (
        bouncer.sql_value(
            "SHOW timezone",
            options="--timezone=Europe/Lisbon  --datestyle=German,\\ YMD",
        )
        == "Europe/Lisbon"
    )

    assert (
        bouncer.sql_value(
            "SHOW timezone",
            options="-c t\\imezone=\\E\\u\\r\\o\\pe/Lisbon  -c    dat\\estyle\\=\\Ge\\rman,\\ YMD",
        )
        == "Europe/Lisbon"
    )

    # extra_float_digits is in ignore_startup_parameters so setting it has no
    # effect, and the default of 1 will still be used.
    assert (
        bouncer.sql_value("SHOW extra_float_digits", options="-c extra_float_digits=2")
        == "1"
    )

    with pytest.raises(
        psycopg.OperationalError,
        match="unsupported options startup parameter: only '-c config=val' and '--config=val' are allowed",
    ):
        bouncer.test(options="-d")

    with pytest.raises(
        psycopg.OperationalError,
        match="unsupported options startup parameter: only '-c config=val' and '--config=val' are allowed",
    ):
        bouncer.test(options="-c timezone")

    with pytest.raises(
        psycopg.OperationalError,
        match="unsupported startup parameter in options: enable_seqscan",
    ):
        bouncer.test(options="-c enable_seqscan=false")

    bouncer.admin("set ignore_startup_parameters = options")
    # Unsupported values should be ignored, so it shouldn't error but it should
    # have its default value instead.
    assert (
        bouncer.sql_value(
            "SHOW enable_seqscan",
            options="-c enable_seqscan=false",
        )
        == "on"
    )

    # Even though we have options in ignore_startup_parameters, we still parse
    # and configure any values in it that we support
    assert (
        bouncer.sql_value(
            "SHOW timezone",
            options="-ctimezone=Europe/Lisbon  -cdatestyle=German,\\ YMD",
        )
        == "Europe/Lisbon"
    )


def test_startup_packet_larger_than_pktbuf(bouncer):
    long_string = "1" * PKT_BUF_SIZE
    bouncer.test(options=f"-c extra_float_digits={long_string}")


def test_empty_application_name(bouncer):
    with bouncer.cur(dbname="p1", application_name="") as cur:
        assert cur.execute("SHOW application_name").fetchone()[0] == ""
        cur.execute("SET application_name = test")
        assert cur.execute("SHOW application_name").fetchone()[0] == "test"

    with bouncer.cur(dbname="p1", application_name="") as cur:
        assert cur.execute("SHOW application_name").fetchone()[0] == ""
        cur.execute("SET application_name = test")
        assert cur.execute("SHOW application_name").fetchone()[0] == "test"


def test_equivalent_startup_param(bouncer):
    bouncer.admin("set verbose=2")

    canonical_expected_times = 1 if PG_MAJOR_VERSION >= 14 else 0
    with bouncer.cur(options="-c DateStyle=ISO") as cur:
        with bouncer.log_contains(
            "varcache_apply: .*SET DateStyle='ISO'", times=1
        ), bouncer.log_contains(
            "varcache_set_canonical: setting DateStyle to its canonical version ISO -> ISO, MDY",
            times=canonical_expected_times,
        ):
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")


@pytest.mark.skipif("WINDOWS", reason="Windows doesn't support sending SIGTERM")
async def test_repeated_sigterm(bouncer):
    with bouncer.cur() as cur:
        cur.execute("SELECT 1")
        bouncer.sigterm()

        # Single sigterm should wait for clients
        time.sleep(1)
        cur.execute("SELECT 1")
        assert bouncer.running()

        # Second sigterm should cause fast exit
        bouncer.sigterm()
        await bouncer.wait_for_exit()
        with pytest.raises(
            psycopg.OperationalError,
            match="database removed|server closed the connection unexpectedly",
        ):
            cur.execute("SELECT 1")
        assert not bouncer.running()


@pytest.mark.skipif("WINDOWS", reason="Windows doesn't support sending SIGINT")
async def test_repeated_sigint(bouncer):
    bouncer.admin(f"set pool_mode=session")
    with bouncer.cur() as cur:
        cur.execute("SELECT 1")
        bouncer.sigint()

        # Single sigint should wait for servers to be released
        time.sleep(1)
        cur.execute("SELECT 1")
        assert bouncer.running()

        # But new clients should be rejected, because we stopped listening for
        # new connections.
        with pytest.raises(psycopg.OperationalError, match="Connection refused"):
            bouncer.test()

        # Second sigint should cause fast exit
        bouncer.sigint()
        await bouncer.wait_for_exit()
        with pytest.raises(
            psycopg.OperationalError,
            match="database removed|server closed the connection unexpectedly",
        ):
            cur.execute("SELECT 1")
        assert not bouncer.running()


def test_newly_paused_client_during_wait_for_servers_shutdown(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    with bouncer.transaction() as cur1, bouncer.cur() as cur2:
        cur1.execute("SELECT 1")
        bouncer.admin("SHUTDOWN WAIT_FOR_SERVERS")
        # Still in the same transaction, so this should work
        cur1.execute("SELECT 1")
        # New transaction so this should fail
        with bouncer.log_contains(r"closing because: server shutting down"):
            with pytest.raises(psycopg.OperationalError):
                cur2.execute("SELECT 1")


async def test_already_paused_client_during_wait_for_servers_shutdown(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set default_pool_size=1")
    bouncer.default_db = "p1"
    with bouncer.transaction() as cur1:
        conn2 = await bouncer.aconn()
        cur2 = conn2.cursor()

        cur1.execute("SELECT 1")
        # start the request before the shutdown
        task = asyncio.ensure_future(cur2.execute("SELECT 1"))
        # We wait so that the client goes to CL_WAITING state
        done, pending = await asyncio.wait([task], timeout=3)
        assert done == set()
        assert pending == {task}
        bouncer.admin("SHUTDOWN WAIT_FOR_SERVERS")
        # Still in the same transaction, so this should work
        cur1.execute("SELECT 1")
        # New transaction so this should fail
        with bouncer.log_contains(r"closing because: server shutting down"):
            with pytest.raises(psycopg.OperationalError):
                await task


@pytest.mark.skipif(
    "not USE_UNIX_SOCKETS", reason="This test does not apply to non unix sockets"
)
def test_shutdown_wait_for_servers(bouncer):
    """
    Test that after issuing `SHUTDOWN WAIT_FOR_SERVERS` pgbouncer
    is no longer accessible via 127.0.0.1 but is still accessible
    on UNIX socket until the last client leaves the pgbouncer instance.
    """

    socket_directory = bouncer.config_dir if LINUX else "/tmp"
    with bouncer.cur() as cur, bouncer.admin_runner.cur():

        def run_blocked_query():
            cur.execute("SELECT pg_sleep(5)")
            cur.fetchone()

        thread = threading.Thread(target=run_blocked_query)
        thread.start()

        bouncer.admin("SHUTDOWN WAIT_FOR_SERVERS")

        time.sleep(2)

        with pytest.raises(psycopg.errors.OperationalError):
            bouncer.test(host=bouncer.config_dir)

        bouncer.admin("SHOW VERSION", host=socket_directory)

        with pytest.raises(psycopg.errors.OperationalError):
            bouncer.test(host="127.0.0.1")

        thread.join(timeout=10)

    # Wait for janitor to close unix socket
    time.sleep(2)

    with pytest.raises(psycopg.errors.OperationalError):
        bouncer.test(host=socket_directory)


@pytest.mark.skipif(
    "not USE_UNIX_SOCKETS", reason="This test does not apply to non unix sockets"
)
def test_shutdown_wait_for_clients(bouncer):
    """
    Test that after issuing `SHUTDOWN WAIT_FOR_CLIENTS` pgbouncer
    is no longer accessible via 127.0.0.1 but is still accessible
    on UNIX socket until the last client leaves the pgbouncer instance.
    """
    socket_directory = bouncer.config_dir if LINUX else "/tmp"
    with bouncer.cur() as cur, bouncer.admin_runner.cur():
        cur.execute(";")
        bouncer.admin("SHUTDOWN WAIT_FOR_CLIENTS")

        time.sleep(2)

        with pytest.raises(psycopg.errors.OperationalError):
            bouncer.test(host=bouncer.config_dir)

        bouncer.admin("SHOW VERSION", host=socket_directory)

        with pytest.raises(psycopg.errors.OperationalError):
            bouncer.test(host="127.0.0.1")

    # Wait for janitor to close unix socket
    time.sleep(2)

    with pytest.raises(psycopg.errors.OperationalError):
        bouncer.test(host=socket_directory)


def test_resume_during_shutdown(bouncer):
    with bouncer.cur() as cur, bouncer.admin_runner.cur() as admin_cur:
        cur.execute("SELECT 1")
        bouncer.admin("SHUTDOWN WAIT_FOR_CLIENTS")

        with pytest.raises(
            psycopg.errors.ProtocolViolation, match="pooler is shutting down"
        ):
            admin_cur.execute("RESUME")


def test_sigusr2_during_shutdown(bouncer):
    with bouncer.cur() as cur:
        cur.execute("SELECT 1")
        bouncer.admin("SHUTDOWN WAIT_FOR_CLIENTS")

        if not WINDOWS:
            with bouncer.log_contains(r"got SIGUSR2 while shutting down, ignoring"):
                bouncer.sigusr2()
                time.sleep(1)


def test_issue_1104(bouncer):
    # regression test for GitHub issue #1104 [PgCredentials objects are freed incorrectly]

    for i in range(1, 15):
        config = """
            [databases]
        """

        for j in range(1, 10 * i):
            config += f"""
                testdb_{i}_{j} = host={bouncer.pg.host} port={bouncer.pg.port} user=dummy_user_{i}_{j}
            """

        config += f"""
            [pgbouncer]
            listen_addr = {bouncer.host}
            listen_port = {bouncer.port}

            auth_type = trust
            auth_file = {bouncer.auth_path}

            admin_users = pgbouncer

            logfile = {bouncer.log_path}
        """

        with bouncer.run_with_config(config):
            bouncer.admin("RELOAD")
