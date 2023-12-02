import subprocess
import psycopg
import pytest

from test import utils


def test_no_database(bouncer):
    with bouncer.log_contains(r"closing because: no such database: nosuchdb"):
        with pytest.raises(
            psycopg.OperationalError, match="no such database: nosuchdb"
        ):
            bouncer.test(dbname="nosuchdb")


def test_no_database_authfail(bouncer):
    bouncer.admin(f"set auth_type='md5'")
    with bouncer.log_contains(r"closing because: password authentication failed"):
        with pytest.raises(
            psycopg.OperationalError, match="password authentication failed"
        ):
            bouncer.test(dbname="nosuchdb", password="wrong")


def test_no_database_auth_user(bouncer):
    bouncer.admin(f"set auth_user='pswcheck'")
    bouncer.admin(f"set auth_type='md5'")
    with bouncer.log_contains(r"closing because: password authentication failed"):
        with pytest.raises(
            psycopg.OperationalError, match="password authentication failed"
        ):
            bouncer.test(dbname="nosuchdb", user="someuser", password="wrong")


def test_no_database_md5_auth_scram_pw_success(bouncer):
    # Testing what happens on successful SCRAM auth connection to non-existent
    # DB Segfaults have been seen after mock authentication was put in place
    # with md5 auth and a scram PW when saving SCRAM credentials. Including
    # this test to check for the condition repeating.
    bouncer.admin(f"set auth_type='md5'")
    with bouncer.log_contains(r"closing because: no such database: nosuchdb"):
        with pytest.raises(
            psycopg.OperationalError, match="no such database: nosuchdb"
        ):
            bouncer.test(dbname="nosuchdb", user="scramuser1", password="foo")


def test_no_database_scram_auth_scram_pw_success(bouncer):
    # Testing what happens on successful SCRAM auth with a SCRAM PW connection
    # to non-existent DB. Segfaults have been seen after mock authentication
    # was put in place with md5 auth and a scram PW. Including this test for
    # completeness.
    bouncer.admin(f"set auth_type='scram-sha-256'")
    with bouncer.log_contains(r"closing because: no such database: nosuchdb"):
        with pytest.raises(
            psycopg.OperationalError, match="no such database: nosuchdb"
        ):
            bouncer.test(dbname="nosuchdb", user="scramuser1", password="foo")


@pytest.mark.md5
def test_no_database_md5_auth_md5_pw_success(bouncer):
    # Testing what happens on successful MD5 auth with a MD5 pw connection to
    # non-existent DB Segfaults have been seen after mock authentication was
    # put in place with md5 auth and a scram PW. Including this test for
    # completeness.
    bouncer.admin(f"set auth_type='md5'")
    with bouncer.log_contains(r"closing because: no such database: nosuchdb"):
        with pytest.raises(
            psycopg.OperationalError, match="no such database: nosuchdb"
        ):
            bouncer.test(dbname="nosuchdb", user="muser1", password="foo")


def test_autodb_database_does_not_exist(bouncer):
    config = f"""
        [databases]
        * = host={bouncer.pg.host} port={bouncer.pg.port} auth_user=postgres password=password
        [pgbouncer]
        listen_addr = {bouncer.host}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
    """
    with bouncer.run_with_config(config):
        with bouncer.log_contains(r"closing because: database \"fake\" does not exist"):
            with pytest.raises(subprocess.CalledProcessError):
                utils.run(["psql", f"port={bouncer.port} host={bouncer.host} dbname=fake"], shell=False)
