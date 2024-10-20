import getpass
import re
import subprocess
import time

import psycopg
import pytest

from .utils import (
    FREEBSD,
    LONG_PASSWORD,
    MACOS,
    PG_SUPPORTS_SCRAM,
    TLS_SUPPORT,
    WINDOWS,
)


@pytest.mark.md5
def test_auth_user(bouncer):
    bouncer.default_db = "authdb"
    bouncer.admin(f"set auth_type='md5'")
    bouncer.test(user="someuser", password="anypasswd")

    with pytest.raises(psycopg.OperationalError, match="no such user"):
        bouncer.test(user="nouser", password="anypasswd")

    with pytest.raises(
        psycopg.OperationalError, match="(SASL|password) authentication failed"
    ):
        bouncer.test(user="someuser", password="badpasswd")


@pytest.mark.md5
def test_auth_dbname_global(bouncer):
    bouncer.admin(f"set auth_dbname='authdb'")
    bouncer.admin(f"set auth_user='pswcheck'")
    bouncer.admin(f"set auth_type='md5'")

    bouncer.test(dbname="p7a", user="someuser", password="anypasswd")
    bouncer.test(dbname="p7a", user="pswcheck", password="pgbouncer-check")


@pytest.mark.md5
def test_auth_dbname_global_invalid(bouncer):
    bouncer.admin(f"set auth_dbname='p_unconfigured_auth_dbname'")
    bouncer.admin(f"set auth_type='md5'")

    with bouncer.log_contains(
        'authentication database "p_unconfigured_auth_dbname" is not configured'
    ):
        with pytest.raises(psycopg.OperationalError, match="bouncer config error"):
            bouncer.test(dbname="authdb", user="someuser", password="anypasswd")

    # test if auth_dbname specified in connection string takes precedence over
    # global setting. This automatically tests that the local logic works.
    bouncer.test(dbname="pauthz", user="someuser", password="anypasswd")


def test_auth_dbname_disabled(bouncer):
    bouncer.admin("disable authdb")
    bouncer.admin(f"set auth_type='md5'")

    with pytest.raises(
        psycopg.OperationalError, match='authentication database "authdb" is disabled'
    ):
        bouncer.test(dbname="pauthz", user="someuser", password="anypasswd")


@pytest.mark.md5
def test_auth_dbname_with_auto_database(bouncer):
    with bouncer.ini_path.open() as f:
        original = f.read()
    with bouncer.ini_path.open("w") as f:
        # uncomment the auto-database line and add auth_dbname to it
        new = re.sub(
            r"^;\* = ", "* = auth_dbname=authdb ", original, flags=re.MULTILINE
        )
        print(new)
        f.write(new)
    bouncer.admin("reload")
    bouncer.admin("set verbose=2")
    bouncer.admin("set auth_user='pswcheck'")
    bouncer.admin(f"set auth_type='md5'")
    # postgres is not defined in test.ini
    bouncer.test(dbname="postgres", user="someuser", password="anypasswd")
    bouncer.test(dbname="postgres", user="pswcheck", password="pgbouncer-check")


@pytest.mark.md5
def test_unconfigured_auth_database_with_auto_database(bouncer):
    """
    Tests the scenario where the authentication database does not
    have a connection string configured under [databases] section.
    However, there is an auto-datatabase, '*', configured. The expectation
    is to use the wild card connection string for the auth_database.
    """
    with bouncer.ini_path.open() as f:
        original = f.read()
        assert (
            re.search(r"^unconfigured_auth_database", original, flags=re.MULTILINE)
            is None
        )
    with bouncer.ini_path.open("w") as f:
        # uncomment the auto-database line
        new = re.sub(r"^;\* = ", "* = ", original, flags=re.MULTILINE)
        print(new)
        f.write(new)
    # configure the auth_dbname to a database that is not configured
    # expected behavior is to fallback to auto-database and auto-register.
    bouncer.admin("set auth_dbname=unconfigured_auth_database")
    bouncer.admin("reload")
    bouncer.admin("set auth_user='pswcheck'")
    bouncer.admin(f"set auth_type='md5'")

    # test a database that does not exist on the server, it should fail.
    # but this error will only surface when we attempt to make the connection to client's
    # database. Hence, we can conclude that we were able to look up the password using
    # auth_dbname
    with pytest.raises(
        psycopg.OperationalError,
        match='database "this_database_doesnt_exist" does not exist',
    ):
        bouncer.test(dbname="this_database_doesnt_exist", user="muser1", password="foo")
    # do a final sanity check that we can connect.
    bouncer.test(user="muser1", password="foo")


def run_server_auth_test(bouncer, dbname):
    bouncer.admin(f"set auth_type='trust'")
    # good password from ini
    bouncer.test(dbname=dbname)
    # bad password from ini
    with pytest.raises(
        psycopg.OperationalError, match="password authentication failed"
    ):
        bouncer.test(dbname=f"{dbname}x")
    # good password from auth_file
    bouncer.test(dbname=f"{dbname}y")
    # bad password from auth_file
    with pytest.raises(
        psycopg.OperationalError, match="password authentication failed"
    ):
        bouncer.test(dbname=f"{dbname}z")


# Test plain-text password authentication from PgBouncer to PostgreSQL server
#
# The PostgreSQL server no longer supports storing plain-text
# passwords, so the server-side user actually uses md5 passwords in
# this test case, but the communication is still in plain text.
def test_password_server(bouncer):
    run_server_auth_test(bouncer, "p4")
    # long password from auth_file
    bouncer.test(dbname="p4l")


@pytest.mark.md5
def test_md5_server(bouncer):
    run_server_auth_test(bouncer, "p5")


@pytest.mark.skipif("not PG_SUPPORTS_SCRAM")
def test_scram_server(bouncer):
    # good password from ini
    bouncer.test(dbname="p6")
    # bad password from ini
    with pytest.raises(
        psycopg.OperationalError, match="password authentication failed"
    ):
        bouncer.test(dbname="p6x")
    # good password from auth_file, but it is not supported with SCRAM
    with pytest.raises(psycopg.OperationalError, match="wrong password type"):
        bouncer.test(dbname="p6y")
    # bad password from auth_file
    with pytest.raises(psycopg.OperationalError, match="wrong password type"):
        bouncer.test(dbname="p6z")


@pytest.mark.md5
def connect_with_password_client_users(bouncer):
    # good password
    bouncer.test(user="puser1", password="foo")
    # bad password
    with pytest.raises(
        psycopg.OperationalError, match="(password|SASL) authentication failed"
    ):
        bouncer.test(user="puser1", password="wrong")


def connect_with_md5_client_users(bouncer):
    # good password
    bouncer.test(user="muser1", password="foo")
    # bad password
    with pytest.raises(
        psycopg.OperationalError, match="password authentication failed"
    ):
        bouncer.test(user="muser1", password="wrong")


def connect_with_scram_client_users(bouncer):
    # users with a stored SCRAM password
    bouncer.test(user="scramuser1", password="foo")
    # bad password
    with pytest.raises(
        psycopg.OperationalError, match="(password|SASL) authentication failed"
    ):
        bouncer.test(user="scramuser1", password="wrong")


# Test plain-text password authentication from client to PgBouncer
@pytest.mark.md5
def test_password_client(bouncer):
    bouncer.admin(f"set auth_type='plain'")
    connect_with_password_client_users(bouncer)
    connect_with_md5_client_users(bouncer)
    connect_with_scram_client_users(bouncer)

    # long password
    bouncer.test(user="longpass", password=LONG_PASSWORD)
    # too long password
    with pytest.raises(
        psycopg.OperationalError, match="password authentication failed"
    ):
        bouncer.test(user="longpass", password="X" + LONG_PASSWORD)


@pytest.mark.md5
def test_md5_client(bouncer):
    bouncer.admin(f"set auth_type='md5'")
    connect_with_password_client_users(bouncer)
    connect_with_md5_client_users(bouncer)
    connect_with_scram_client_users(bouncer)


def test_scram_client(bouncer):
    bouncer.admin(f"set auth_type='scram-sha-256'")
    connect_with_password_client_users(bouncer)
    connect_with_scram_client_users(bouncer)

    # cannot authenticate to MD5 stored passwords with SCRAM auth
    # good password
    with pytest.raises(
        psycopg.OperationalError, match="(password|SASL) authentication failed"
    ):
        bouncer.test(user="muser1", password="foo")
    # bad password
    with pytest.raises(
        psycopg.OperationalError, match="(password|SASL) authentication failed"
    ):
        bouncer.test(user="muser1", password="wrong")


@pytest.mark.skipif("not PG_SUPPORTS_SCRAM")
def test_scram_both(bouncer):
    bouncer.admin(f"set auth_type='scram-sha-256'")

    # plain-text password in userlist.txt
    bouncer.test(dbname="p61", user="scramuser3", password="baz")

    # SCRAM password in userlist.txt
    bouncer.test(dbname="p62", user="scramuser1", password="foo")


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_auth_dbname_usage(
    bouncer,
):
    """
    Check that the pgbouncer handles correctly the reserved pgbouncer
    database usage as an authentication database
    """

    config = f"""
        [databases]
        pgbouncer_test = host={bouncer.pg.host} port={bouncer.pg.port} auth_dbname=pgbouncer
        * = host={bouncer.host} port={bouncer.port} auth_dbname=pgbouncer
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.host}
        admin_users = pswcheck
        auth_type = md5
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
    """

    # We expect that stats user does not exist in userlist.txt
    with bouncer.log_contains(
        'cannot use the reserved "pgbouncer" database as an auth_dbname', 3
    ):
        with bouncer.run_with_config(config):
            #     Check the pgbouncer does not crash when we connect to pgbouncer admin db
            with pytest.raises(psycopg.OperationalError, match="bouncer config error"):
                bouncer.sql(
                    query="show stats",
                    user="stats",
                    password="stats",
                    dbname="pgbouncer",
                )

            #     Check the pgbouncer does not crash when explicitly pgbouncer database
            #     (admin DB) was set in auth_dbname in the databases definition section
            with pytest.raises(psycopg.OperationalError, match="bouncer config error"):
                bouncer.sql(
                    query="show stats",
                    user="stats",
                    password="stats",
                    dbname="pgbouncer_test",
                )

            #     Check the pgbouncer does not crash when explicitly pgbouncer database
            #     (admin DB) was set in auth_dbname in the autodb definition
            with pytest.raises(psycopg.OperationalError, match="bouncer config error"):
                bouncer.sql(
                    query="show stats", user="stats", password="stats", dbname="p4"
                )


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_auth_dbname_usage_global_setting(
    bouncer,
):
    """
    Check that the pgbouncer does not apply config which contains
    explicitly "pgbouncer" database (admin DB) set in [pgbouncer] section
    """

    config = f"""
        [databases]
        * = host={bouncer.host} port={bouncer.port}
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.host}
        admin_users = pswcheck
        auth_type = md5
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = pgbouncer
    """

    with bouncer.log_contains(
        'cannot use the reserved "pgbouncer" database as an auth_dbname', 1
    ):
        with bouncer.run_with_config(config):
            pass


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_auth_query_database_setting(
    bouncer,
):
    """
    Check the pgbouncer can use auth_query in database section to get password
    """

    config = f"""
        [databases]
        postgres = auth_query='SELECT usename, passwd FROM pg_shadow where usename = $1'\
            host={bouncer.pg.host} port={bouncer.pg.port}
        [pgbouncer]
        auth_query = SELECT 1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = md5
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres
    """

    with bouncer.run_with_config(config):
        with bouncer.run_with_config(config):
            bouncer.sql(
                query="select version()",
                user="stats",
                password="stats",
                dbname="postgres",
            )

    config = f"""
        [databases]
        postgres = auth_query='SELECT usename, substring(passwd,1,3) FROM pg_shadow where usename = $1'\
            host={bouncer.pg.host} port={bouncer.pg.port}
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = md5
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres
    """

    with bouncer.run_with_config(config):
        with pytest.raises(
            psycopg.OperationalError, match="password authentication failed"
        ):
            with bouncer.run_with_config(config):
                bouncer.sql(
                    query="select version()",
                    user="stats",
                    password="stats",
                    dbname="postgres",
                )


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_auth_query_works_with_configured_users(bouncer):
    """
    Check that when a user is configured with per-user options, but missing from auth_file
    pgBouncer will still attempt to valididate passwords if auth_query is configured.
    """

    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = md5
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres
        pool_mode = session
        [users]
        puser1 = pool_mode=statement
    """

    # As a sanity check, make sure that a user with a password in auth_file cannot run transactions
    # while configured to be in statement pooling mode
    with bouncer.run_with_config(config):
        with pytest.raises(psycopg.OperationalError):
            with bouncer.log_contains(
                "closing because: transaction blocks not allowed in statement pooling mode"
            ):
                bouncer.sql(
                    query="begin",
                    user="puser1",
                    password="foo",
                    dbname="postgres",
                )

    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = md5
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres
        pool_mode = session
        [users]
        stats = pool_mode=statement
    """

    # While pgbouncer is set to use session mode by default, the stats user
    # is set to use statement pooling. pgBouncer should fail to allow a begin
    # statement while in statement pooling mode, but still be able to authenticate
    # using auth_query.
    with bouncer.run_with_config(config):
        with pytest.raises(psycopg.OperationalError):
            with bouncer.log_contains(
                "closing because: transaction blocks not allowed in statement pooling mode"
            ):
                bouncer.sql(
                    query="begin",
                    user="stats",
                    password="stats",
                    dbname="postgres",
                )


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_auth_query_logs_server_error(
    bouncer,
):
    """
    Check that when the auth_query response has an error, pgbouncer logs
    the error message provided by postgres.
    """

    config = f"""
        [databases]
        postgres = auth_query='SELECT usename, passwd FROM not_pg_shadow where usename = $1'\
            host={bouncer.pg.host} port={bouncer.pg.port}
        [pgbouncer]
        auth_query = SELECT 1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = md5
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres
    """

    with bouncer.log_contains('"not_pg_shadow" does not exist'):
        with bouncer.run_with_config(config):
            with pytest.raises(psycopg.OperationalError, match="bouncer config error"):
                bouncer.sql(
                    query="select version()",
                    user="stats",
                    password="stats",
                    dbname="postgres",
                )


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
@pytest.mark.md5
def test_auth_dbname_works_fine(
    bouncer,
):
    """
    Check that we handle correctly all positive cases of auth_dbname usage
    """

    config = f"""
        [databases]
        postgres_authdb1 = host={bouncer.pg.host} port={bouncer.pg.port} dbname=postgres auth_dbname=postgres
        postgres_authdb2 = host={bouncer.pg.host} port={bouncer.pg.port} dbname=postgres auth_dbname=postgres
        pgbouncer2pgbpouncer = host={bouncer.host} port={bouncer.port} dbname=pgbouncer auth_dbname=postgres_authdb2
        pgbouncer2pgbpouncer_global = host={bouncer.host} port={bouncer.port} dbname=pgbouncer
        postgres_test = host={bouncer.host} port={bouncer.port}
        * = host={bouncer.pg.host} port={bouncer.pg.port} auth_dbname=postgres
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = md5
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres_authdb1
    """

    with bouncer.run_with_config(config):
        # The client connects to pgbouncer (admin DB) using userlist.txt file match
        bouncer.sql(
            query="show stats", user="pgbouncer", password="fake", dbname="pgbouncer"
        )

        # The client connects to pgbouncer (admin DB) using auth_query, pgbouncer must
        # use postgres_authdb1 as an auth DB, that defined in [pgbouncer] section
        bouncer.sql(
            query="show stats", user="stats", password="stats", dbname="pgbouncer"
        )

        # The client connects to pgbouncer2pgbpouncer DB which redirects
        # to pgbouncer (admin DB) itself, pgbouncer must use postgres_authdb2, which
        # is defined in the database definition
        bouncer.sql(
            query="show stats",
            user="stats",
            password="stats",
            dbname="pgbouncer2pgbpouncer",
        )

        # The client connects to pgbouncer2pgbpouncer_global DB which redirects
        # to pgbouncer (admin DB) itself, pgbouncer must use postgres_authdb1, which
        # is defined in [pgbouncer] section
        bouncer.sql(
            query="show stats",
            user="stats",
            password="stats",
            dbname="pgbouncer2pgbpouncer_global",
        )

        # The client connects to admin DB directly
        # pgbouncer must use postgres_authdb1, which is defined in [pgbouncer] section
        bouncer.sql(
            query="show stats", user="stats", password="stats", dbname="pgbouncer"
        )

        # The client connects to postgres DB that matches with autodb
        # pgbouncer must use postgres_authdb1, which is defined in [pgbouncer] section
        bouncer.test(user="stats", password="stats", dbname="postgres")


def test_hba_leak(bouncer):
    """
    Don't actually check if HBA auth works, but check that it doesn't leak
    memory when using the feature.
    """
    bouncer.write_ini(f"auth_type = hba")
    bouncer.write_ini(f"auth_hba_file = hba_test.rules")

    bouncer.admin("reload")

    bouncer.write_ini(f"auth_type = trust")

    bouncer.admin("reload")

    bouncer.write_ini(f"auth_type = hba")

    bouncer.admin("reload")
    bouncer.admin("reload")


async def test_change_server_password_reconnect(bouncer, pg):
    bouncer.default_db = "p4"
    bouncer.admin(f"set default_pool_size=1")
    bouncer.admin(f"set pool_mode=transaction")
    try:
        # good password, opens connection
        bouncer.test()
        pg.sql("ALTER USER puser1 PASSWORD 'bar'")
        # works fine because server connection is still open
        bouncer.test()
        with bouncer.transaction() as cur1:
            # Claim the connection
            cur1.execute("select 1")
            # Because of our fast client closure on server auth failures (see
            # kill_pool_logins), we should only have one connection failing at
            # the postgres side. But we should still have 3 failing at the
            # pgbouncer side.
            with pg.log_contains(
                r"password authentication failed", times=1
            ), bouncer.log_contains(
                r"closing because: password authentication failed for user", times=3
            ):
                result1 = bouncer.atest()
                result2 = bouncer.atest()
                result3 = bouncer.atest()

                # Mark the old connection as dirty
                bouncer.admin("reconnect")
                # Trigger new connection creation
                bouncer.admin(f"set default_pool_size=2")
                with pytest.raises(
                    psycopg.OperationalError, match="password authentication failed"
                ):
                    await result1
                with pytest.raises(
                    psycopg.OperationalError, match="password authentication failed"
                ):
                    await result2
                with pytest.raises(
                    psycopg.OperationalError, match="password authentication failed"
                ):
                    await result3
    finally:
        pg.sql("ALTER USER puser1 PASSWORD 'foo'")


async def test_change_server_password_server_lifetime(bouncer, pg):
    bouncer.default_db = "p4"
    bouncer.admin(f"set default_pool_size=1")
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set server_lifetime=1")
    try:
        # good password, opens connection
        bouncer.test()
        pg.sql("ALTER USER puser1 PASSWORD 'bar'")
        # wait until server disconnect
        time.sleep(3)

        # Because of our fast client closure on server auth failures (see
        # kill_pool_logins), we should only have one connection failing at
        # the postgres side. But we should still have 3 failing at the
        # pgbouncer side.
        with pg.log_contains(
            r"password authentication failed", times=1
        ), bouncer.log_contains(
            r"closing because: password authentication failed for user", times=3
        ):
            result1 = bouncer.atest()
            result2 = bouncer.atest()
            result3 = bouncer.atest()

            with pytest.raises(psycopg.OperationalError):
                await result1
            with pytest.raises(psycopg.OperationalError):
                await result2
            with pytest.raises(psycopg.OperationalError):
                await result3
    finally:
        pg.sql("ALTER USER puser1 PASSWORD 'foo'")


@pytest.mark.skipif("MACOS", reason="SSL tests are broken on OSX in CI #1031")
@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
@pytest.mark.skipif(not TLS_SUPPORT, reason="pgbouncer is built without TLS support")
def test_client_hba_cert(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"

    bouncer.write_ini(f"client_tls_key_file = {key}")
    bouncer.write_ini(f"client_tls_cert_file = {cert}")
    bouncer.write_ini(f"client_tls_ca_file = {root}")
    bouncer.write_ini(f"client_tls_sslmode = require")
    bouncer.write_ini(f"auth_type = hba")
    bouncer.write_ini(
        f"auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1"
    )
    bouncer.write_ini(f"auth_user = pswcheck")
    bouncer.write_ini(f"auth_file = {bouncer.auth_path}")
    bouncer.write_ini(f"auth_hba_file = pgbouncer_hba.conf")
    bouncer.write_ini(f"auth_ident_file = pgident.conf")

    bouncer.admin("reload")

    client_key = cert_dir / "TestCA1" / "sites" / "04-pgbouncer.acme.org.key"
    client_cert = cert_dir / "TestCA1" / "sites" / "04-pgbouncer.acme.org.crt"

    # The client connects to p0x using a client certificate with CN=pgbouncer.acme.org.
    # hba_eval returns the following line:
    #    hostssl p0x    all        0.0.0.0/0               cert    map=test
    # where "test" map is defined in pgident.conf as
    #    test            pgbouncer.acme.org      someuser
    #    test            pgbouncer.acme.org      anotheruser
    # hence the test succeeds.
    bouncer.psql_test(
        dbname="p0x",
        host="localhost",
        user="someuser",
        sslmode="verify-full",
        sslkey=client_key,
        sslcert=client_cert,
        sslrootcert=root,
    )

    bouncer.pg.sql("create user anotheruser with login;")

    # The client connects to p0x using a client certificate with CN=pgbouncer.acme.org.
    # hba_eval returns the following line:
    #    hostssl p0x    all        0.0.0.0/0               cert    map=test
    # where "test" map is defined in pgident.conf as
    #    test            pgbouncer.acme.org      someuser
    #    test            pgbouncer.acme.org      anotheruser
    # hence the test succeeds.
    bouncer.psql_test(
        dbname="p0x",
        host="localhost",
        user="anotheruser",
        sslmode="verify-full",
        sslkey=client_key,
        sslcert=client_cert,
        sslrootcert=root,
    )

    # The client connects to p0x using a client certificate with CN=pgbouncer.acme.org.
    # hba_eval returns the following line:
    #    hostssl p0x    all        0.0.0.0/0               cert    map=test
    # where "test" map is defined in pgident.conf as
    #    test            pgbouncer.acme.org      someuser
    #    test            pgbouncer.acme.org      anotheruser
    # the username 'bouncer' does not match any mapped pg-username.
    # hence the test fails.
    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        with bouncer.log_contains(
            "p0x/bouncer@127.0.0.1:43544 ident map: test does not have a match"
        ):
            bouncer.psql_test(
                dbname="p0x",
                host="localhost",
                user="bouncer",
                sslmode="verify-full",
                sslkey=client_key,
                sslcert=client_cert,
                sslrootcert=root,
            )

    client_key = cert_dir / "TestCA1" / "sites" / "02-bouncer.key"
    client_cert = cert_dir / "TestCA1" / "sites" / "02-bouncer.crt"

    # The client connects to p0 using a client certificate with CN=bouncer.
    # hba_eval returns the following line:
    #    hostssl p0              bouncer         0.0.0.0/0               cert
    # CN expected in map is "bouncer" which matches the CN in the client cert
    # hence the test succeeds.
    bouncer.psql_test(
        dbname="p0",
        host="localhost",
        user="bouncer",
        sslmode="verify-full",
        sslkey=client_key,
        sslcert=client_cert,
        sslrootcert=root,
    )

    # The client connects to p0y using a client certificate with CN=bouncer.
    # hba_eval returns the following line:
    #    hostssl p0y             all             0.0.0.0/0               cert    map=test2
    # where
    #   test2           bouncer                 all
    #   test2           pgbouncer.acme.org      "anotheruser"
    # test2 mapping allows any client with CN="bouncer" to connect using any user name.
    # Hence the test succeeds.
    bouncer.psql_test(
        dbname="p0y",
        host="localhost",
        user="someuser",
        sslmode="verify-full",
        sslkey=client_key,
        sslcert=client_cert,
        sslrootcert=root,
    )

    client_key = cert_dir / "TestCA1" / "sites" / "04-pgbouncer.acme.org.key"
    client_cert = cert_dir / "TestCA1" / "sites" / "04-pgbouncer.acme.org.crt"

    # The client connects to p0y using a client certificate with CN=pgbouncer.acme.org.
    # hba_eval returns the following line:
    #    hostssl p0y             all             0.0.0.0/0               cert    map=test2
    # where
    #   test2           bouncer                 all
    #   test2           pgbouncer.acme.org      "anotheruser"
    # for CN=pgbouncer.acme.org, test2 allows to use anotheruser. Hence the test fails.

    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        with bouncer.log_contains(
            "p0y/someuser@127.0.0.1:39712 ident map: test2 does not have a match"
        ):
            bouncer.psql_test(
                dbname="p0y",
                host="localhost",
                user="someuser",
                sslmode="verify-full",
                sslkey=client_key,
                sslcert=client_cert,
                sslrootcert=root,
            )

    # The client connects to p0y using a client certificate with CN=pgbouncer.acme.org.
    # hba_eval returns the following line:
    #    hostssl p0y             all             0.0.0.0/0               cert    map=test2
    # where
    #   test2           bouncer                 all
    #   test2           pgbouncer.acme.org      "anotheruser"
    # for CN=pgbouncer.acme.org, test2 allows to use anotheruser. Hence the test succeeds.

    bouncer.psql_test(
        dbname="p0y",
        host="localhost",
        user="anotheruser",
        sslmode="verify-full",
        sslkey=client_key,
        sslcert=client_cert,
        sslrootcert=root,
    )


@pytest.mark.skipif("WINDOWS", reason="Windows does not have peer authentication")
def test_peer_auth_ident_map(bouncer):
    cur_user = getpass.getuser()

    ident_conf_file = bouncer.config_dir / "ident.conf"
    hba_conf_file = bouncer.config_dir / "hba.conf"

    with open(ident_conf_file, "w") as f:
        f.write(f"mymap {cur_user} postgres\n")
        f.write(f"mymap {cur_user} someuser\n")

    with open(hba_conf_file, "w") as f:
        f.write(f"local   all  all peer map=mymap")

    bouncer.write_ini(f"auth_type = hba")
    bouncer.write_ini(
        f"auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1"
    )
    bouncer.write_ini(f"auth_user = pswcheck")
    bouncer.write_ini(f"auth_file = {bouncer.auth_path}")
    bouncer.write_ini(f"auth_hba_file = {hba_conf_file}")
    bouncer.write_ini(f"auth_ident_file = {ident_conf_file}")

    bouncer.admin("reload")

    bouncer.psql_test(
        dbname="p0y",
        host=f"{bouncer.admin_host}",
        user="postgres",
    )

    bouncer.psql_test(
        dbname="p0y",
        host=f"{bouncer.admin_host}",
        user="someuser",
    )

    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        with bouncer.log_contains(
            "p0y/bouncer@unix(6202):10202 ident map mymap cannot be matched"
        ):
            bouncer.psql_test(
                dbname="p0y",
                host=f"{bouncer.admin_host}",
                user="bouncer",
            )

    with open(ident_conf_file, "w") as f:
        f.write(f"mymap {cur_user} all")

    bouncer.admin("reload")

    bouncer.psql_test(
        dbname="p0",
        host=f"{bouncer.admin_host}",
        user="bouncer",
    )


async def test_auth_user_trust_auth_without_auth_file_set(bouncer) -> None:
    """
    This is a regression test for issue #1116, using the SET command
    """
    bouncer.admin("set auth_user='pswcheck_not_in_auth_file'")
    bouncer.admin("set auth_type='trust'")
    with bouncer.conn(
        dbname="p7a",
        user="pswcheck_not_in_auth_file",
    ) as cn:
        with cn.cursor() as cur:
            cur.execute("select 1")


def test_auth_user_trust_auth_without_auth_file_reload(bouncer) -> None:
    """
    This is a regression test for issue #1116, using the RELOAD command
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} dbname=postgres port={bouncer.pg.port} min_pool_size=2

        [pgbouncer]
        listen_addr = {bouncer.host}
        listen_port = {bouncer.port}
        auth_type = trust
        auth_user = pswcheck_not_in_auth_file
        auth_dbname = postgres
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_file = {bouncer.auth_path}
    """

    with bouncer.run_with_config(config):
        with bouncer.conn(
            dbname="postgres",
            user="postgres",
        ) as cn:
            with cn.cursor() as cur:
                cur.execute("select 1")


def test_auth_user_at_db_level_trust_auth_without_auth_file_reload(bouncer) -> None:
    """
    This is a regression test for issue #1116, when auth_user was set at the
    database level
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} dbname=postgres port={bouncer.pg.port} min_pool_size=2 auth_user=pswcheck_not_in_auth_file

        [pgbouncer]
        listen_addr = {bouncer.host}
        listen_port = {bouncer.port}
        auth_type = trust
        auth_dbname = postgres
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_file = {bouncer.auth_path}
    """

    with bouncer.run_with_config(config):
        with bouncer.conn(
            dbname="postgres",
            user="pswcheck_not_in_auth_file",
        ) as cn:
            with cn.cursor() as cur:
                cur.execute("select 1")


def test_auth_user_with_same_forced_user(bouncer):
    """
    Check that the pgbouncer correctly handles multiple credentials with the
    same name with a global auth_user (isue #1103).
    """

    config = f"""
        [databases]
        * = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres min_pool_size=2
        [pgbouncer]
        listen_addr = {bouncer.host}
        listen_port = {bouncer.port}
        auth_type = trust
        auth_user = postgres
        auth_dbname = postgres
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_file = {bouncer.auth_path}
    """

    with bouncer.run_with_config(config):
        # Let's get an error "no such user"
        with pytest.raises(psycopg.OperationalError, match="no such user"):
            bouncer.conn(dbname="dummydb2", user="dummyuser2", password="dummypswd2")
        # Let's wait a few seconds for the janitor to kick in and crash pgbouncer
        time.sleep(2)
        # Now we will try to connect with OK parameters
        with bouncer.conn(dbname="p3", user="postgres", password="asdasd") as cn:
            with cn.cursor() as cur:
                cur.execute("select 1")


def test_auth_user_at_db_level_with_same_forced_user(bouncer):
    """
    Check that the pgbouncer correctly handles multiple credentials with the
    same name with auth_user for the specific database (isue #1103).
    """

    config = f"""
        [databases]
        * = host={bouncer.pg.host} port={bouncer.pg.port} auth_user=postgres user=postgres min_pool_size=2
        [pgbouncer]
        listen_addr = {bouncer.host}
        listen_port = {bouncer.port}
        auth_type = trust
        auth_dbname = postgres
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_file = {bouncer.auth_path}
    """

    with bouncer.run_with_config(config):
        # Let's get an error "no such user"
        with pytest.raises(psycopg.OperationalError, match="no such user"):
            bouncer.conn(dbname="dummydb2", user="dummyuser2", password="dummypswd2")
        # Let's wait a few seconds for the janitor to kick in and crash pgbouncer
        time.sleep(2)
        # Now we will try to connect with OK parameters
        with bouncer.conn(dbname="p3", user="postgres", password="asdasd") as cn:
            with cn.cursor() as cur:
                cur.execute("select 1")
