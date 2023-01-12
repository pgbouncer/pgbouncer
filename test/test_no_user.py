import psycopg
import pytest

# Several tests that check the behavior when connecting with a
# nonexistent user under various authentication types.  Database p1
# has a forced user, p2 does not; these exercise slightly different
# code paths.


def test_no_user_trust(bouncer):
    bouncer.admin(f"set auth_type='trust'")
    with bouncer.log_contains(r'closing because: "trust" authentication failed'):
        with pytest.raises(
            psycopg.OperationalError, match='"trust" authentication failed'
        ):
            bouncer.test(dbname="p2", user="nosuchuser")


def test_no_user_trust_forced_user(bouncer):
    bouncer.admin(f"set auth_type='trust'")
    with bouncer.log_contains(r'closing because: "trust" authentication failed'):
        with pytest.raises(
            psycopg.OperationalError, match='"trust" authentication failed'
        ):
            bouncer.test(dbname="p1", user="nosuchuser")


def test_no_user_password(bouncer):
    bouncer.admin(f"set auth_type='plain'")
    with bouncer.log_contains(r"closing because: password authentication failed"):
        with pytest.raises(
            psycopg.OperationalError, match="password authentication failed"
        ):
            bouncer.test(dbname="p2", user="nosuchuser", password="whatever")


def test_no_user_password_forced_user(bouncer):
    bouncer.admin(f"set auth_type='plain'")
    with bouncer.log_contains(r"closing because: password authentication failed"):
        with pytest.raises(
            psycopg.OperationalError, match="password authentication failed"
        ):
            bouncer.test(dbname="p1", user="nosuchuser", password="whatever")


def test_no_user_md5(bouncer):
    bouncer.admin(f"set auth_type='md5'")
    with bouncer.log_contains(r"closing because: password authentication failed"):
        with pytest.raises(
            psycopg.OperationalError, match="password authentication failed"
        ):
            bouncer.test(dbname="p2", user="nosuchuser", password="whatever")


def test_no_user_md5_forced_user(bouncer):
    bouncer.admin(f"set auth_type='md5'")
    with bouncer.log_contains(r"closing because: password authentication failed"):
        with pytest.raises(
            psycopg.OperationalError, match="password authentication failed"
        ):
            bouncer.test(dbname="p1", user="nosuchuser", password="whatever")


def test_no_user_scram(bouncer):
    bouncer.admin(f"set auth_type='scram-sha-256'")
    with bouncer.log_contains(r"closing because: SASL authentication failed"):
        with pytest.raises(
            psycopg.OperationalError, match="SASL authentication failed"
        ):
            bouncer.test(dbname="p2", user="nosuchuser", password="whatever")


def test_no_user_scram_forced_user(bouncer):
    bouncer.admin(f"set auth_type='scram-sha-256'")
    with bouncer.log_contains(r"closing because: SASL authentication failed"):
        with pytest.raises(
            psycopg.OperationalError, match="SASL authentication failed"
        ):
            bouncer.test(dbname="p1", user="nosuchuser", password="whatever")


def test_no_user_auth_user(bouncer):
    bouncer.admin(f"set auth_type='md5'")
    # Currently no mock authentication when using
    # auth_query/auth_user.  See TODO in
    # handle_auth_query_response().
    with bouncer.log_contains(r"closing because: no such user \(age"):
        with pytest.raises(psycopg.OperationalError, match="no such user"):
            bouncer.test(dbname="authdb", user="nosuchuser", password="whatever")
