import re
import time

import psycopg
import pytest

from .utils import LONG_PASSWORD, PG_SUPPORTS_SCRAM, WINDOWS


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


def test_auth_dbname_global(bouncer):
    bouncer.admin(f"set auth_dbname='authdb'")
    bouncer.admin(f"set auth_user='pswcheck'")
    bouncer.admin(f"set auth_type='md5'")

    bouncer.test(dbname="p7a", user="someuser", password="anypasswd")


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
