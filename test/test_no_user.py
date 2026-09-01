import socket
import struct

import psycopg
import pytest

# Several tests that check the behavior when connecting with a
# nonexistent user under various authentication types.  Database p1
# has a forced user, p2 does not; these exercise slightly different
# code paths.


def _recv_message(stream):
    message_type = stream.read(1)
    message_length = struct.unpack("!I", stream.read(4))[0]
    return message_type, stream.read(message_length - 4)


def test_no_user_trust(bouncer):
    bouncer.admin(f"set auth_type='trust'")
    with (
        bouncer.log_contains(r'closing because: "trust" authentication failed'),
        pytest.raises(psycopg.OperationalError, match='"trust" authentication failed'),
    ):
        bouncer.test(dbname="p2", user="nosuchuser")


def test_no_user_trust_forced_user(bouncer):
    bouncer.admin(f"set auth_type='trust'")
    with (
        bouncer.log_contains(r'closing because: "trust" authentication failed'),
        pytest.raises(psycopg.OperationalError, match='"trust" authentication failed'),
    ):
        bouncer.test(dbname="p1", user="nosuchuser")


def test_no_user_password(bouncer):
    bouncer.admin(f"set auth_type='plain'")
    with (
        bouncer.log_contains(r"closing because: password authentication failed"),
        pytest.raises(psycopg.OperationalError, match="password authentication failed"),
    ):
        bouncer.test(dbname="p2", user="nosuchuser", password="whatever")


def test_no_user_password_forced_user(bouncer):
    bouncer.admin(f"set auth_type='plain'")
    with (
        bouncer.log_contains(r"closing because: password authentication failed"),
        pytest.raises(psycopg.OperationalError, match="password authentication failed"),
    ):
        bouncer.test(dbname="p1", user="nosuchuser", password="whatever")


def test_no_user_md5(bouncer):
    bouncer.admin(f"set auth_type='md5'")
    with (
        bouncer.log_contains(r"closing because: password authentication failed"),
        pytest.raises(psycopg.OperationalError, match="password authentication failed"),
    ):
        bouncer.test(dbname="p2", user="nosuchuser", password="whatever")


@pytest.mark.md5
def test_no_user_repeated_startup(bouncer):
    bouncer.admin("set auth_type='md5'")
    parameters = b"user\0nosuchuser\0database\0p2\0\0"
    payload = struct.pack("!I", 0x30000) + parameters
    startup = struct.pack("!I", len(payload) + 4) + payload

    with (
        socket.create_connection((bouncer.host, bouncer.port), timeout=2) as sock,
        sock.makefile("rb") as stream,
    ):
        sock.sendall(startup)
        message_type, message = _recv_message(stream)
        assert message_type == b"R"
        assert struct.unpack("!I", message[:4])[0] == 5

        with bouncer.log_contains(r"client re-sent startup pkt"):
            sock.sendall(startup)
            message_type, message = _recv_message(stream)
            assert message_type == b"E"
            assert b"client re-sent startup pkt" in message

    assert bouncer.admin_value("show version")


def test_no_user_md5_forced_user(bouncer):
    bouncer.admin(f"set auth_type='md5'")
    with (
        bouncer.log_contains(r"closing because: password authentication failed"),
        pytest.raises(psycopg.OperationalError, match="password authentication failed"),
    ):
        bouncer.test(dbname="p1", user="nosuchuser", password="whatever")


def test_no_user_scram(bouncer):
    bouncer.admin(f"set auth_type='scram-sha-256'")
    with (
        bouncer.log_contains(r"closing because: SASL authentication failed"),
        pytest.raises(psycopg.OperationalError, match="SASL authentication failed"),
    ):
        bouncer.test(dbname="p2", user="nosuchuser", password="whatever")


def test_no_user_scram_forced_user(bouncer):
    bouncer.admin(f"set auth_type='scram-sha-256'")
    with (
        bouncer.log_contains(r"closing because: SASL authentication failed"),
        pytest.raises(psycopg.OperationalError, match="SASL authentication failed"),
    ):
        bouncer.test(dbname="p1", user="nosuchuser", password="whatever")


def test_no_user_auth_user(bouncer):
    bouncer.admin(f"set auth_type='md5'")
    # Currently no mock authentication when using
    # auth_query/auth_user.  See TODO in
    # handle_auth_query_response().
    with (
        bouncer.log_contains(r"closing because: no such user \(age"),
        pytest.raises(psycopg.OperationalError, match="no such user"),
    ):
        bouncer.test(dbname="authdb", user="nosuchuser", password="whatever")
