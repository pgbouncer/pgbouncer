import re

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
def test_connection_with_missing_stats_user_and_enabled_auth_query_without_global_auth_dbname(
    bouncer,
):
    """
    Regression for https://github.com/pgbouncer/pgbouncer/issues/314

    Check that pgbouncer is not crashing on connection to the virtual pgbouncer virtual db when user is missing in
    userlists.txt and auth_query enabled.

    It covers case when global auth_dbname does not set and target database used for auth_dbname in auth query
    """

    config = f"""
        [databases]
        * = host={bouncer.pg.host} port={bouncer.pg.port}
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.pg.host}
        verbose = 2
        admin_users = pswcheck
        auth_file = userlist.txt
        listen_port = {bouncer.port}
    """

    # good password
    bouncer.test(user="pgbouncer", password="fake")

    with bouncer.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="bouncer config error"):
            # bad password
            # We expect that stats user does not exist ether in userlist.txt and in postgresql DB
            bouncer.test(user="stats", password="stats", dbname="pgbouncer")


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_connection_with_missing_stats_user_and_enabled_auth_query_with_global_auth_dbname(
    bouncer,
):
    """
    Regression for https://github.com/pgbouncer/pgbouncer/issues/314

    Check that pgbouncer is not crashing on connection to the virtual pgbouncer virtual db when user is missing in
    userlists.txt and auth_query enabled.

    It covers case when global auth_dbname is set globally
    """

    config = f"""
        [databases]
        * = host={bouncer.pg.host} port={bouncer.pg.port}
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.pg.host}
        verbose = 2
        admin_users = pswcheck
        auth_file = userlist.txt
        auth_dbname = pgbouncer
        listen_port = {bouncer.port}
    """

    # good password
    bouncer.test(user="pgbouncer", password="fake")

    with bouncer.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="bouncer config error"):
            # bad password
            # We expect that stats user does not exist ether in userlist.txt and in postgresql DB
            bouncer.test(user="stats", password="stats", dbname="pgbouncer")


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_connection_with_missing_stats_user_and_enabled_auth_query_with_explicitly_authdb_name_in_db_def(
    bouncer,
):
    """
    Regression for https://github.com/pgbouncer/pgbouncer/issues/314

    Check that pgbouncer is not crashing on connection to the virtual pgbouncer virtual db when user is missing in
    userlists.txt and auth_query enabled.

    It covers case when database definition contains explicitly defined authdb_name
    """

    config = f"""
        [databases]
        * = host={bouncer.pg.host} port={bouncer.pg.port}
        pgbouncer_test = host={bouncer.pg.host} port={bouncer.pg.port} auth_dbname="pgbouncer"
        [pgbouncer]
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = pswcheck
        stats_users = stats
        listen_addr = {bouncer.pg.host}
        verbose = 2
        admin_users = pswcheck
        auth_file = userlist.txt
        auth_dbname = pgbouncer
        listen_port = {bouncer.port}
    """

    # good password
    bouncer.test(user="pgbouncer", password="fake")

    with bouncer.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="bouncer config error"):
            # bad password
            # We expect that stats user does not exist ether in userlist.txt and in postgresql DB
            bouncer.test(user="stats", password="stats", dbname="pgbouncer_test")
