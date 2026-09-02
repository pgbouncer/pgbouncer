"""
GSSAPI (Kerberos) authentication tests for PgBouncer.

Requires a running KDC (set up by test/setup_kdc.sh) and pgbouncer built
with --with-gssapi.  Tests are skipped automatically if either is not
available.
"""

import os
import socket
import ssl
import struct
import subprocess

import psycopg
import pytest

from .utils import GSS_SUPPORT, TLS_SUPPORT, WINDOWS

REALM = "TEST.PGBOUNCER"
USER_PRINCIPAL = f"testuser@{REALM}"
USER_PASSWORD = "testpass"
KEYTAB = "/tmp/pgbouncer-test.keytab"


def kdc_is_running():
    """Check if the test KDC is running and the keytab exists."""
    if not os.path.exists(KEYTAB):
        return False
    try:
        result = subprocess.run(
            ["klist", "-k", "-t", KEYTAB],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


KDC_AVAILABLE = kdc_is_running()

pytestmark = [
    pytest.mark.skipif(WINDOWS, reason="GSSAPI tests not supported on Windows"),
    pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer built without GSSAPI"),
    pytest.mark.skipif(
        not KDC_AVAILABLE,
        reason="test KDC not running (run test/setup_kdc.sh first)",
    ),
]


def kinit():
    """Acquire a TGT for the test user."""
    subprocess.run(
        ["kinit", USER_PRINCIPAL],
        input=USER_PASSWORD.encode() + b"\n",
        check=True,
        capture_output=True,
        timeout=10,
    )


def kdestroy():
    """Destroy the credential cache."""
    subprocess.run(["kdestroy"], capture_output=True, timeout=5, check=False)


def setup_module(module):
    """Acquire test user credentials before running tests."""
    kinit()


def teardown_module(module):
    """Clean up credentials."""
    kdestroy()


def gss_bouncer_config(bouncer, pg, *, auth_type="gssapi", extra=""):
    """Generate a pgbouncer config for GSSAPI testing."""
    return f"""\
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {bouncer.port}
auth_type = {auth_type}
auth_gssapi_keytab = {KEYTAB}
logfile = {bouncer.log_path}
pidfile =
unix_socket_dir = {bouncer.config_dir}
admin_users = testuser
{extra}

[databases]
p0 = host=127.0.0.1 port={pg.port} dbname=p0 user=testuser
"""


def gss_hba_config(bouncer, pg, *, hba_content, extra=""):
    """Generate a pgbouncer config with HBA-based GSSAPI."""
    hba_file = bouncer.config_dir / "gss_hba.conf"
    with open(hba_file, "w") as f:
        f.write(hba_content + "\n")
    return f"""\
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {bouncer.port}
auth_type = hba
auth_hba_file = {hba_file}
auth_gssapi_keytab = {KEYTAB}
logfile = {bouncer.log_path}
pidfile =
unix_socket_dir = {bouncer.config_dir}
admin_users = testuser
{extra}

[databases]
p0 = host=127.0.0.1 port={pg.port} dbname=p0 user=testuser
"""


def test_gssapi_auth_type(pg, bouncer):
    """auth_type = gssapi works end-to-end."""
    config = gss_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )

        kdestroy()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )

    kinit()


def test_gssapi_auth_warm_pool_second_login(pg, bouncer):
    """Two sequential GSSAPI logins to the same pool; the second hits a warm
    pool (welcome cached), exercising the finish_client_login==true path."""
    config = gss_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )


def test_gssapi_hba(pg, bouncer):
    """auth_type = hba with gssapi method works."""
    config = gss_hba_config(
        bouncer,
        pg,
        hba_content="host all all 0.0.0.0/0 gssapi",
    )
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )


def test_gssapi_wrong_username(pg, bouncer):
    """Client claiming a wrong username is rejected by gss_localname mismatch."""
    pg.sql("DROP ROLE IF EXISTS wronguser", gssencmode="disable")
    pg.sql("CREATE ROLE wronguser LOGIN", gssencmode="disable")

    config = gss_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI|principal mapping"):
            bouncer.test(
                user="wronguser",
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )


def test_gssapi_no_ticket(pg, bouncer):
    """Connection fails when the client has no TGT."""
    config = gss_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kdestroy()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )

    kinit()


def test_gssapi_gssencmode_prefer(pg, bouncer):
    """Connection with gssencmode=prefer (libpq's default) works.

    The client offers GSSAPI encryption first; with client_gssencmode=disable
    pgbouncer declines it, and libpq falls back to a plain-text connection and
    completes GSSAPI authentication over that channel.
    """
    config = gss_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="prefer"
        )


def test_gssapi_gssencmode_disable(pg, bouncer):
    """Connection with gssencmode=disable works."""
    config = gss_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )


def test_gssapi_backend_auth(pg, bouncer):
    """Full path: client GSSAPI to pgbouncer, pgbouncer GSSAPI to postgres.

    Postgres is configured with krb_server_keyfile in conftest.py (session
    scope).  This test adds a GSS HBA line so postgres requires GSSAPI from
    pgbouncer's backend connection.
    """
    with pg.hba_path.open() as f:
        old_hba = f.read()
    with pg.hba_path.open("w") as f:
        f.write("host all testuser 127.0.0.1/32 gss include_realm=0\n")
        f.write(old_hba)
    pg.reload()

    config = gss_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser",
            dbname="p0",
            sslmode="disable",
            gssencmode="disable",
        )


def test_gssapi_hba_include_realm_warning(pg, bouncer):
    """HBA line with include_realm=0 is accepted with a warning, not rejected."""
    config = gss_hba_config(
        bouncer,
        pg,
        hba_content="host all all 0.0.0.0/0 gssapi include_realm=0",
    )
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )
        with open(bouncer.log_path) as f:
            assert 'GSSAPI option "include_realm=0" is ignored' in f.read()


def test_gssapi_hba_map_rejected(pg, bouncer):
    """HBA line with a restrictive map= is rejected (fail closed).

    map= restricts which principals may authenticate. pgbouncer maps principals
    via auth_to_local, so honoring map= as a no-op would grant more access than
    the administrator wrote. The line is rejected rather than silently ignored,
    so with it as the only rule the connection has no matching HBA entry.
    """
    ident_file = bouncer.config_dir / "gss_ident.conf"
    with open(ident_file, "w") as f:
        f.write("gssmap testuser nonexistent_user\n")

    config = gss_hba_config(
        bouncer,
        pg,
        hba_content="host all all 0.0.0.0/0 gssapi map=gssmap",
        extra=f"auth_ident_file = {ident_file}",
    )
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
            )
        with open(bouncer.log_path) as f:
            assert 'restrictive GSSAPI option "map=gssmap" is not supported' in f.read()


def test_gssapi_wrong_service_name(pg, bouncer):
    """auth_gssapi_service_name = wrongname causes backend auth failure.

    Postgres is configured with GSS auth so the wrong service name actually
    prevents pgbouncer from authenticating to the backend.
    """
    with pg.hba_path.open() as f:
        old_hba = f.read()
    with pg.hba_path.open("w") as f:
        f.write("host all testuser 127.0.0.1/32 gss include_realm=0\n")
        f.write(old_hba)
    pg.reload()

    config = gss_bouncer_config(
        bouncer,
        pg,
        extra="auth_gssapi_service_name = wrongname",
    )
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )


def test_gssapi_missing_keytab(pg, bouncer):
    """Pgbouncer with a nonexistent keytab rejects GSSAPI connections."""
    config = gss_bouncer_config(bouncer, pg).replace(KEYTAB, "/nonexistent/path.keytab")
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )


# --------------------------------------------------------------------------
# GSSAPI encryption tests
# --------------------------------------------------------------------------


def gss_enc_bouncer_config(bouncer, pg, *, extra=""):
    """Generate a pgbouncer config with GSS encryption enabled."""
    return f"""\
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {bouncer.port}
auth_type = gssapi
auth_gssapi_keytab = {KEYTAB}
client_gssencmode = allow
server_gssencmode = disable
logfile = {bouncer.log_path}
pidfile =
unix_socket_dir = {bouncer.config_dir}
admin_users = testuser
{extra}

[databases]
p0 = host=127.0.0.1 port={pg.port} dbname=p0 user=testuser
"""


def test_gssapi_gssencmode_require_client(pg, bouncer):
    """Client with gssencmode=require connects when pgbouncer allows GSS enc."""
    config = gss_enc_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
        )


def test_gssapi_gssencmode_require_rejected(pg, bouncer):
    """Client with gssencmode=require is rejected when pgbouncer disables GSS enc."""
    config = gss_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="require",
            )


def test_gssapi_enc_mitm_plaintext_rejected(pg, bouncer):
    """Plaintext pipelined with a GSSENCRequest is rejected before the handshake.

    Mirrors postgres: if data is already buffered when the GSSENCRequest is
    processed, it arrived unencrypted and may have been injected by a
    man-in-the-middle, so the connection is refused rather than upgraded. A
    correct pgbouncer never answers 'G' in this case.
    """
    config = gss_enc_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        gssencreq = struct.pack("!ii", 8, 80877104)
        s = socket.create_connection(("127.0.0.1", bouncer.port), timeout=5)
        try:
            # Send the request and injected plaintext in a single segment so
            # pgbouncer buffers both before it processes the GSSENCRequest.
            s.sendall(gssencreq + b"injected-plaintext-not-a-gss-token")
            resp = s.recv(1024)
        finally:
            s.close()
        assert not resp.startswith(b"G"), f"handshake must not start; got {resp!r}"


@pytest.mark.skipif(not TLS_SUPPORT, reason="pgbouncer built without TLS")
def test_gssapi_enc_req_after_tls_rejected(pg, bouncer, cert_dir):
    """A GSSENCRequest after encryption is already established is refused.

    pgbouncer must not re-negotiate encryption once a secure channel exists;
    postgres threads ssl_done/gss_done for exactly this, refusing a second
    SSL/GSS request. Establish TLS, then send a GSSENCRequest over it: pgbouncer
    must reject rather than answer 'G' and start a second handshake (which would
    also leak the existing GSS context/credentials on the acceptor side).
    """
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    config = f"""\
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {bouncer.port}
auth_type = gssapi
auth_gssapi_keytab = {KEYTAB}
client_gssencmode = allow
client_tls_sslmode = allow
client_tls_cert_file = {cert}
client_tls_key_file = {key}
logfile = {bouncer.log_path}
pidfile =
unix_socket_dir = {bouncer.config_dir}
admin_users = testuser

[databases]
p0 = host=127.0.0.1 port={pg.port} dbname=p0 user=testuser
"""
    with bouncer.run_with_config(config):
        raw = socket.create_connection(("127.0.0.1", bouncer.port), timeout=5)
        raw.sendall(struct.pack("!ii", 8, 80877103))  # SSLRequest
        assert raw.recv(1) == b"S"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        try:
            tls.sendall(struct.pack("!ii", 8, 80877104))  # GSSENCRequest over TLS
            tls.settimeout(5)
            # Rejection closes the connection without sending 'G'; EOF, a TLS
            # error, or a timeout all mean the re-negotiation was refused.
            try:
                resp = tls.recv(1024)
            except (ssl.SSLError, OSError):
                resp = b""
        finally:
            tls.close()
        assert not resp.startswith(b"G"), (
            f"re-negotiation must be refused; got {resp!r}"
        )


def test_gssapi_enc_and_auth(pg, bouncer):
    """Full round-trip: client uses GSSAPI encryption and GSSAPI auth to
    pgbouncer; pgbouncer uses trust to the backend."""
    config = gss_enc_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
        )


def test_gssapi_server_gssencmode_require(pg, bouncer):
    """Full round-trip with server_gssencmode=require.

    Both client and backend use GSS encryption. The backend postgres in the
    test container supports GSS encryption, so this succeeds.
    """
    config = gss_enc_bouncer_config(bouncer, pg, extra="server_gssencmode = require")
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser",
            dbname="p0",
            sslmode="disable",
            gssencmode="require",
        )


def test_gssapi_server_gssencmode_prefer_fallback(pg, bouncer):
    """pgbouncer falls back gracefully when backend sends N and prefer is set."""
    config = gss_enc_bouncer_config(bouncer, pg, extra="server_gssencmode = prefer")
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
        )


def test_gssapi_server_gssencmode_prefer_no_creds_fallback(pg, bouncer):
    """server_gssencmode=prefer falls back when pgbouncer has no initiator creds.

    The test backend supports GSS encryption, so it would answer 'G'. With
    prefer and no usable credential cache, pgbouncer must not offer GSS to the
    backend (which it could not complete); it connects over plain-text instead.
    Mirrors libpq, which skips GSS when pg_GSS_have_cred_cache() finds nothing.
    Client uses trust so it needs no ticket; only the backend path is exercised.
    """
    auth_file = bouncer.config_dir / "gss_trust_userlist.txt"
    with open(auth_file, "w") as f:
        f.write('"testuser" "trust-unused"\n')
    config = gss_bouncer_config(
        bouncer,
        pg,
        auth_type="trust",
        extra=f"auth_file = {auth_file}\nserver_gssencmode = prefer",
    )
    with bouncer.run_with_config(config):
        kdestroy()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )
    kinit()


def test_gssapi_enc_backend_gss_auth(pg, bouncer):
    """Full path: client GSS-encrypted, backend GSS-encrypted + GSS-authenticated."""
    with pg.hba_path.open() as f:
        old_hba = f.read()
    with pg.hba_path.open("w") as f:
        f.write("host all testuser 127.0.0.1/32 gss include_realm=0\n")
        f.write(old_hba)
    pg.reload()

    config = gss_enc_bouncer_config(bouncer, pg, extra="server_gssencmode = require")
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser",
            dbname="p0",
            sslmode="disable",
            gssencmode="require",
        )


def test_gssapi_enc_wrong_username(pg, bouncer):
    """Encrypted channel established, but username mismatch still rejected."""
    pg.sql("DROP ROLE IF EXISTS wronguser", gssencmode="disable")
    pg.sql("CREATE ROLE wronguser LOGIN", gssencmode="disable")

    config = gss_enc_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI|principal mapping"):
            bouncer.test(
                user="wronguser",
                dbname="p0",
                sslmode="disable",
                gssencmode="require",
            )


def test_gssapi_enc_no_ticket(pg, bouncer):
    """Encrypted channel cannot be established without a TGT."""
    config = gss_enc_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kdestroy()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="require",
            )

    kinit()


def test_gssapi_client_gssencmode_require_rejects_plaintext(pg, bouncer):
    """client_gssencmode=require refuses unencrypted client connections.

    This mirrors the sslmode=require behavior: a plain-text StartupMessage is
    rejected, while a GSS-encrypted client is accepted.
    """
    config = gss_enc_bouncer_config(bouncer, pg, extra="client_gssencmode = require")
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
            )
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
        )


def test_gssapi_enc_does_not_bypass_password_auth(pg, bouncer):
    """GSS encryption must not bypass the configured non-GSS auth method.

    With auth_type=plain and client_gssencmode=allow, a GSS-encrypted client
    still has to complete the configured password exchange; encryption and
    authentication are orthogonal. The identity shortcut applies only when the
    configured method is itself GSSAPI. Without a password the connection is
    rejected; with the correct password the exchange runs over the encrypted
    channel and succeeds.
    """
    auth_file = bouncer.config_dir / "gss_plain_userlist.txt"
    with open(auth_file, "w") as f:
        f.write('"testuser" "supersecret"\n')

    config = gss_enc_bouncer_config(
        bouncer, pg, extra=f"auth_type = plain\nauth_file = {auth_file}"
    )
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
            )
        bouncer.test(
            user="testuser",
            dbname="p0",
            sslmode="disable",
            gssencmode="require",
            password="supersecret",
        )


def test_gssapi_enc_large_payload(pg, bouncer):
    """Payloads larger than PQ_GSS_MAX_PACKET_SIZE (16 KB) round-trip in both
    directions, exercising the multi-packet gss_wrap()/gss_unwrap() framing.
    """
    config = gss_enc_bouncer_config(bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        conn = {
            "user": "testuser",
            "dbname": "p0",
            "sslmode": "disable",
            "gssencmode": "require",
        }
        n = 100000
        # server -> client: large result, pgbouncer encrypts the outbound stream
        assert bouncer.sql_value(f"select repeat('x', {n})", **conn) == "x" * n
        # client -> server: large bind parameter, pgbouncer decrypts the inbound stream
        assert (
            bouncer.sql_value("select length(%s::text)", params=("y" * n,), **conn) == n
        )
