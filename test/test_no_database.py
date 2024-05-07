import re

import psycopg
import pytest


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


def test_no_database_pg(bouncer):
    with bouncer.log_contains(
        r'server login failed: FATAL database "non_existing_pg_db" does not exist'
    ), bouncer.log_contains(
        r'closing because: database "non_existing_pg_db" does not exist'
    ):
        with pytest.raises(
            psycopg.OperationalError,
            match='database "non_existing_pg_db" does not exist',
        ):
            bouncer.test(dbname="non_existing_pg_db")


def test_no_database_auto_database(bouncer):
    with bouncer.ini_path.open() as f:
        original = f.read()
    with bouncer.ini_path.open("w") as f:
        # uncomment the auto-database line
        f.write(re.sub(r"^;\*", "*", original, flags=re.MULTILINE))

    bouncer.admin("reload")

    with bouncer.log_contains(
        r'server login failed: FATAL database "nosuchdb" does not exist'
    ), bouncer.log_contains(r'closing because: database "nosuchdb" does not exist'):
        with pytest.raises(
            psycopg.OperationalError, match='database "nosuchdb" does not exist'
        ):
            bouncer.test(dbname="nosuchdb")


def test_no_database_auto_database_auth_user(bouncer):
    with bouncer.ini_path.open() as f:
        original = f.read()
    with bouncer.ini_path.open("w") as f:
        # uncomment the auto-database line
        f.write(re.sub(r"^;\*", "*", original, flags=re.MULTILINE))

    bouncer.admin("reload")
    bouncer.admin(f"set auth_user='pswcheck'")
    bouncer.admin(f"set auth_type='md5'")

    with bouncer.log_contains(
        r'server login failed: FATAL database "nosuchdb" does not exist'
    ), bouncer.log_contains(r'closing because: database "nosuchdb" does not exist'):
        with pytest.raises(
            psycopg.OperationalError, match='database "nosuchdb" does not exist'
        ):
            bouncer.test(dbname="nosuchdb", user="nonexistinguser")


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
