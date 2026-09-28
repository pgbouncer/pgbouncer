"""
GSSAPI (Kerberos) authentication tests for PgBouncer.

The tests run against the throwaway KDC started by the ``kdc`` fixture in
conftest.py and need pgbouncer built with GSSAPI. That fixture skips them when
GSSAPI is not built in or the krb5 KDC tools are missing, or fails them if
REQUIRE_GSSAPI_TESTS is set.
"""

import ctypes
import ctypes.util
import socket
import ssl
import struct
import subprocess

import psycopg
import pytest

from .utils import (
    GSS_USER_PASSWORD,
    GSS_USER_PRINCIPAL,
    KRB5_TOOLS,
    TLS_SUPPORT,
    WINDOWS,
)

pytestmark = pytest.mark.skipif(WINDOWS, reason="GSSAPI tests not supported on Windows")


def kinit():
    """Acquire a TGT for the test user in the fixture's credential cache."""
    subprocess.run(
        [KRB5_TOOLS["kinit"], GSS_USER_PRINCIPAL],
        input=GSS_USER_PASSWORD.encode() + b"\n",
        check=True,
        capture_output=True,
        timeout=10,
    )


def kdestroy():
    """Destroy the credential cache."""
    subprocess.run(
        [KRB5_TOOLS["kdestroy"]], capture_output=True, timeout=5, check=False
    )


@pytest.fixture(autouse=True, scope="module")
def gss_credentials(kdc):
    """Acquire test user credentials before the module and clean up after.

    Depending on the session ``kdc`` fixture guarantees the KDC is running and
    the KRB5_CONFIG/KRB5CCNAME environment is set before kinit runs.
    """
    kinit()
    yield
    kdestroy()


def gss_bouncer_config(kdc, bouncer, pg, *, auth_type="gss", extra=""):
    """Generate a pgbouncer config for GSSAPI testing."""
    return f"""\
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {bouncer.port}
auth_type = {auth_type}
auth_gssapi_keytab = {kdc.keytab}
logfile = {bouncer.log_path}
pidfile =
unix_socket_dir = {bouncer.config_dir}
admin_users = testuser
{extra}

[databases]
p0 = host=127.0.0.1 port={pg.port} dbname=p0 user=testuser
"""


def gss_hba_config(kdc, bouncer, pg, *, hba_content, extra=""):
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
auth_gssapi_keytab = {kdc.keytab}
logfile = {bouncer.log_path}
pidfile =
unix_socket_dir = {bouncer.config_dir}
admin_users = testuser
{extra}

[databases]
p0 = host=127.0.0.1 port={pg.port} dbname=p0 user=testuser
"""


def test_gssapi_auth_type(kdc, pg, bouncer):
    """auth_type = gss works end-to-end."""
    config = gss_bouncer_config(kdc, bouncer, pg)
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


def test_gssapi_auth_warm_pool_second_login(kdc, pg, bouncer):
    """Two sequential GSSAPI logins to the same pool; the second hits a warm
    pool (welcome cached), exercising the finish_client_login==true path."""
    config = gss_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )


@pytest.mark.parametrize("options", ["", " include_realm=1"])
def test_gssapi_hba_full_principal(kdc, pg, bouncer, options):
    """A gss HBA line requires the username to equal the full principal, as
    PostgreSQL's default include_realm=1 does."""
    config = gss_hba_config(
        kdc,
        bouncer,
        pg,
        hba_content=f"host all all 0.0.0.0/0 gss{options}",
    )
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user=GSS_USER_PRINCIPAL,
            dbname="p0",
            sslmode="disable",
            gssencmode="disable",
        )
        with (
            bouncer.log_contains('principal "testuser@TEST.PGBOUNCER" does not match'),
            pytest.raises(psycopg.OperationalError),
        ):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )


def test_gssapi_wrong_username(kdc, pg, bouncer):
    """Client claiming a wrong username is rejected by gss_localname mismatch."""
    pg.sql("DROP ROLE IF EXISTS wronguser", gssencmode="disable")
    pg.sql("CREATE ROLE wronguser LOGIN", gssencmode="disable")

    config = gss_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI|principal mapping"):
            bouncer.test(
                user="wronguser",
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )


def test_gssapi_no_ticket(kdc, pg, bouncer):
    """Connection fails when the client has no TGT."""
    config = gss_bouncer_config(kdc, bouncer, pg)
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


def test_gssapi_gssencmode_prefer(kdc, pg, bouncer):
    """Connection with gssencmode=prefer (libpq's default) works.

    The client offers GSSAPI encryption first; with client_gssencmode=disable
    pgbouncer declines it, and libpq falls back to a plain-text connection and
    completes GSSAPI authentication over that channel.
    """
    config = gss_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="prefer"
        )


def test_gssapi_gssencmode_disable(kdc, pg, bouncer):
    """Connection with gssencmode=disable works."""
    config = gss_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )


def test_gssapi_backend_auth(kdc, pg, bouncer):
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

    config = gss_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser",
            dbname="p0",
            sslmode="disable",
            gssencmode="disable",
        )


def test_gssapi_hba_include_realm_0(kdc, pg, bouncer):
    """include_realm=0 maps the principal through auth_to_local, like the
    global auth_type does."""
    config = gss_hba_config(
        kdc,
        bouncer,
        pg,
        hba_content="host all all 0.0.0.0/0 gss include_realm=0",
    )
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
        )
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user=GSS_USER_PRINCIPAL,
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )


@pytest.mark.parametrize("option", ["map=gssmap", "krb_realm=TEST.PGBOUNCER"])
def test_gssapi_hba_unsupported_option_rejects(kdc, pg, bouncer, option):
    """A gss line with map= or krb_realm=, which pgbouncer does not implement,
    rejects the connections it matches instead of letting a later, broader
    line accept them."""
    config = gss_hba_config(
        kdc,
        bouncer,
        pg,
        hba_content=(
            f"host all all 0.0.0.0/0 gss {option}\n"
            "host all all 0.0.0.0/0 gss include_realm=0"
        ),
    )
    with (
        bouncer.log_contains(f'GSSAPI option "{option}" is not supported'),
        bouncer.run_with_config(config),
    ):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="disable",
            )


def test_gssapi_wrong_service_name(kdc, pg, bouncer):
    """server_gssapi_service_name = wrongname causes backend auth failure.

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
        kdc,
        bouncer,
        pg,
        extra="server_gssapi_service_name = wrongname",
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


def test_gssapi_missing_keytab(kdc, pg, bouncer):
    """Pgbouncer with a nonexistent keytab rejects GSSAPI connections."""
    config = gss_bouncer_config(kdc, bouncer, pg).replace(
        str(kdc.keytab), "/nonexistent/path.keytab"
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


# --------------------------------------------------------------------------
# GSSAPI encryption tests
# --------------------------------------------------------------------------


def gss_enc_bouncer_config(kdc, bouncer, pg, *, extra=""):
    """Generate a pgbouncer config with GSS encryption enabled."""
    return f"""\
[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {bouncer.port}
auth_type = gss
auth_gssapi_keytab = {kdc.keytab}
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


def test_gssapi_gssencmode_require_client(kdc, pg, bouncer):
    """Client with gssencmode=require connects when pgbouncer allows GSS enc."""
    config = gss_enc_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
        )


def test_gssapi_gssencmode_require_rejected(kdc, pg, bouncer):
    """Client with gssencmode=require is rejected when pgbouncer disables GSS enc."""
    config = gss_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser",
                dbname="p0",
                sslmode="disable",
                gssencmode="require",
            )


def test_gssapi_enc_mitm_plaintext_rejected(kdc, pg, bouncer):
    """Plaintext pipelined with a GSSENCRequest is rejected before the handshake.

    Mirrors postgres: if data is already buffered when the GSSENCRequest is
    processed, it arrived unencrypted and may have been injected by a
    man-in-the-middle, so the connection is refused rather than upgraded. A
    correct pgbouncer never answers 'G' in this case.
    """
    config = gss_enc_bouncer_config(kdc, bouncer, pg)
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
def test_gssapi_enc_req_after_tls_rejected(kdc, pg, bouncer, cert_dir):
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
auth_type = gss
auth_gssapi_keytab = {kdc.keytab}
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


def test_gssapi_enc_and_auth(kdc, pg, bouncer):
    """Full round-trip: client uses GSSAPI encryption and GSSAPI auth to
    pgbouncer; pgbouncer uses trust to the backend."""
    config = gss_enc_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
        )


def test_gssapi_server_gssencmode_require(kdc, pg, bouncer):
    """Full round-trip with server_gssencmode=require.

    Both client and backend use GSS encryption. The backend postgres in the
    test container supports GSS encryption, so this succeeds.
    """
    config = gss_enc_bouncer_config(
        kdc, bouncer, pg, extra="server_gssencmode = require"
    )
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser",
            dbname="p0",
            sslmode="disable",
            gssencmode="require",
        )


def test_gssapi_server_gssencmode_prefer_fallback(kdc, pg, bouncer):
    """pgbouncer falls back gracefully when backend sends N and prefer is set."""
    config = gss_enc_bouncer_config(
        kdc, bouncer, pg, extra="server_gssencmode = prefer"
    )
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
        )


def test_gssapi_server_gssencmode_prefer_no_creds_fallback(kdc, pg, bouncer):
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
        kdc,
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


def test_gssapi_enc_backend_gss_auth(kdc, pg, bouncer):
    """Full path: client GSS-encrypted, backend GSS-encrypted + GSS-authenticated."""
    with pg.hba_path.open() as f:
        old_hba = f.read()
    with pg.hba_path.open("w") as f:
        f.write("host all testuser 127.0.0.1/32 gss include_realm=0\n")
        f.write(old_hba)
    pg.reload()

    config = gss_enc_bouncer_config(
        kdc, bouncer, pg, extra="server_gssencmode = require"
    )
    with bouncer.run_with_config(config):
        kinit()
        bouncer.test(
            user="testuser",
            dbname="p0",
            sslmode="disable",
            gssencmode="require",
        )


def test_gssapi_enc_wrong_username(kdc, pg, bouncer):
    """Encrypted channel established, but username mismatch still rejected."""
    pg.sql("DROP ROLE IF EXISTS wronguser", gssencmode="disable")
    pg.sql("CREATE ROLE wronguser LOGIN", gssencmode="disable")

    config = gss_enc_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI|principal mapping"):
            bouncer.test(
                user="wronguser",
                dbname="p0",
                sslmode="disable",
                gssencmode="require",
            )


def test_gssapi_enc_no_ticket(kdc, pg, bouncer):
    """Encrypted channel cannot be established without a TGT."""
    config = gss_enc_bouncer_config(kdc, bouncer, pg)
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


def test_gssapi_client_gssencmode_require_rejects_plaintext(kdc, pg, bouncer):
    """client_gssencmode=require refuses unencrypted client connections.

    This mirrors the sslmode=require behavior: a plain-text StartupMessage is
    rejected, while a GSS-encrypted client is accepted.
    """
    config = gss_enc_bouncer_config(
        kdc, bouncer, pg, extra="client_gssencmode = require"
    )
    with bouncer.run_with_config(config):
        kinit()
        with pytest.raises(psycopg.OperationalError):
            bouncer.test(
                user="testuser", dbname="p0", sslmode="disable", gssencmode="disable"
            )
        bouncer.test(
            user="testuser", dbname="p0", sslmode="disable", gssencmode="require"
        )


def test_gssapi_enc_does_not_bypass_password_auth(kdc, pg, bouncer):
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
        kdc, bouncer, pg, extra=f"auth_type = plain\nauth_file = {auth_file}"
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


def test_gssapi_enc_large_payload(kdc, pg, bouncer):
    """Payloads larger than PQ_GSS_MAX_PACKET_SIZE (16 KB) round-trip in both
    directions, exercising the multi-packet gss_wrap()/gss_unwrap() framing.
    """
    config = gss_enc_bouncer_config(kdc, bouncer, pg)
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


# A minimal GSS-API initiator driven through ctypes, and the wire messages to
# log in with it. libpq always starts a raw krb5 exchange that completes in one
# gss_accept_sec_context() call, so these let a test choose the mechanism and
# request flags that libpq does not.

GSS_C_MUTUAL_FLAG = 2
GSS_C_CONF_FLAG = 16
GSS_C_INTEG_FLAG = 32
GSS_C_DCE_STYLE = 4096
GSS_S_CONTINUE_NEEDED = 1
KRB5_MECH_OID = bytes.fromhex("2a864886f712010202")  # 1.2.840.113554.1.2.2
SPNEGO_MECH_OID = bytes.fromhex("2b0601050502")  # 1.3.6.1.5.5.2
HOSTBASED_SERVICE_OID = bytes.fromhex("2a864886f71201020104")  # 1.2.840.113554.1.2.1.4
AUTH_REQ_OK = 0
AUTH_REQ_GSS = 7
AUTH_REQ_GSS_CONT = 8
GSSENC_REQUEST_CODE = 80877104


class GssBuffer(ctypes.Structure):
    _fields_ = [("length", ctypes.c_size_t), ("value", ctypes.c_void_p)]

    @classmethod
    def of(cls, data):
        return cls(len(data), ctypes.cast(data, ctypes.c_void_p))


class GssOid(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("elements", ctypes.c_char_p)]

    @classmethod
    def of(cls, der):
        return cls(len(der), der)


class GssInitiator:
    """A GSS-API initiator for postgres@127.0.0.1 using the credential cache."""

    def __init__(self, mech_oid, flags):
        self.lib = ctypes.CDLL(ctypes.util.find_library("gssapi_krb5"))
        self.mech = GssOid.of(mech_oid)
        self.flags = flags
        self.context = ctypes.c_void_p()
        self.target = ctypes.c_void_p()
        self._call(
            "gss_import_name",
            ctypes.byref(GssBuffer.of(b"postgres@127.0.0.1")),
            ctypes.byref(GssOid.of(HOSTBASED_SERVICE_OID)),
            ctypes.byref(self.target),
        )

    def _call(self, func, *args):
        minor = ctypes.c_uint32()
        major = getattr(self.lib, func)(ctypes.byref(minor), *args) & 0xFFFFFFFF
        assert major >> 16 == 0, f"{func} failed: major={major:#x} minor={minor.value}"
        return major

    def step(self, token=None):
        """Process pgbouncer's token, if any. Returns (output token, complete)."""
        out = GssBuffer()
        major = self._call(
            "gss_init_sec_context",
            None,
            ctypes.byref(self.context),
            self.target,
            ctypes.byref(self.mech),
            ctypes.c_uint32(self.flags),
            ctypes.c_uint32(0),
            None,
            None if token is None else ctypes.byref(GssBuffer.of(token)),
            None,
            ctypes.byref(out),
            None,
            None,
        )
        return self._take(out), not (major & GSS_S_CONTINUE_NEEDED)

    def wrap(self, data):
        out = GssBuffer()
        self._call(
            "gss_wrap",
            self.context,
            ctypes.c_int(1),
            ctypes.c_uint32(0),
            ctypes.byref(GssBuffer.of(data)),
            None,
            ctypes.byref(out),
        )
        return self._take(out)

    def unwrap(self, data):
        out = GssBuffer()
        self._call(
            "gss_unwrap",
            self.context,
            ctypes.byref(GssBuffer.of(data)),
            ctypes.byref(out),
            None,
            None,
        )
        return self._take(out)

    def _take(self, buf):
        """Copy a buffer the library allocated, then free it."""
        data = ctypes.string_at(buf.value, buf.length)
        self.lib.gss_release_buffer(ctypes.byref(ctypes.c_uint32()), ctypes.byref(buf))
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        minor = ctypes.byref(ctypes.c_uint32())
        self.lib.gss_delete_sec_context(minor, ctypes.byref(self.context), None)
        self.lib.gss_release_name(minor, ctypes.byref(self.target))


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        assert chunk, "pgbouncer closed the connection"
        data += chunk
    return data


def read_message(sock):
    msg_type, length = struct.unpack("!ci", recv_exact(sock, 5))
    return msg_type, recv_exact(sock, length - 4)


def startup_packet():
    body = struct.pack("!i", 196608) + b"user\0testuser\0database\0p0\0\0"
    return struct.pack("!i", len(body) + 4) + body


def gss_login(port, initiator):
    """Log in as testuser, feeding the tokens through the given initiator.

    Returns how many GSSResponse messages the client had to send.
    """
    sent = 0
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(startup_packet())
        complete = False
        while True:
            msg_type, payload = read_message(s)
            assert msg_type == b"R", f"login failed: {msg_type!r} {payload!r}"
            code, data = struct.unpack("!i", payload[:4])[0], payload[4:]
            if code == AUTH_REQ_OK:
                break
            assert code in (AUTH_REQ_GSS, AUTH_REQ_GSS_CONT), f"auth request {code}"
            token, complete = initiator.step(
                data if code == AUTH_REQ_GSS_CONT else None
            )
            if token:
                s.sendall(b"p" + struct.pack("!i", len(token) + 4) + token)
                sent += 1
        assert complete, "pgbouncer accepted the login before the client finished"
        while (msg_type := read_message(s)[0]) != b"Z":
            assert msg_type != b"E", "login failed after authentication"
    return sent


def test_gssapi_multi_round_accept(kdc, pg, bouncer):
    """An exchange where gss_accept_sec_context() returns GSS_S_CONTINUE_NEEDED.

    With GSS_C_DCE_STYLE the krb5 acceptor answers the AP-REQ with an AP-REP
    and CONTINUE_NEEDED, and completes only after the client sends its own
    AP-REP back, so pgbouncer has to keep the context across two client packets.
    """
    config = gss_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        flags = GSS_C_MUTUAL_FLAG | GSS_C_DCE_STYLE
        with GssInitiator(KRB5_MECH_OID, flags) as initiator:
            assert gss_login(bouncer.port, initiator) == 2


def test_gssapi_spnego_client(kdc, pg, bouncer):
    """A client that negotiates krb5 through SPNEGO, as pgjdbc with useSpnego=true
    does, authenticates like a raw krb5 client."""
    config = gss_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        with GssInitiator(SPNEGO_MECH_OID, GSS_C_MUTUAL_FLAG) as initiator:
            assert gss_login(bouncer.port, initiator) == 1


def gss_enc_login(port, initiator):
    """Set up GSS encryption through the given initiator and log in over it.

    Returns how many handshake tokens the client had to send.
    """
    sent = 0
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(struct.pack("!ii", 8, GSSENC_REQUEST_CODE))
        assert recv_exact(s, 1) == b"G"
        token, complete = initiator.step()
        while token:
            s.sendall(struct.pack("!I", len(token)) + token)
            sent += 1
            if complete:
                break
            (length,) = struct.unpack("!I", recv_exact(s, 4))
            token, complete = initiator.step(recv_exact(s, length))
        assert complete

        # Every packet from here on is [length][gss_wrap() output].
        wrapped = initiator.wrap(startup_packet())
        s.sendall(struct.pack("!I", len(wrapped)) + wrapped)
        plaintext = b""
        while not plaintext.endswith(b"Z\0\0\0\5I"):
            assert not plaintext.startswith(b"E"), f"login failed: {plaintext!r}"
            (length,) = struct.unpack("!I", recv_exact(s, 4))
            plaintext += initiator.unwrap(recv_exact(s, length))
        assert plaintext.startswith(b"R\0\0\0\x08\0\0\0\0"), plaintext[:64]
    return sent


def test_gssapi_enc_multi_round_accept(kdc, pg, bouncer):
    """The GSS encryption handshake, when gss_accept_sec_context() returns
    GSS_S_CONTINUE_NEEDED. The same DCE-style exchange as above, followed by a
    login over the encrypted channel.
    """
    config = gss_enc_bouncer_config(kdc, bouncer, pg)
    with bouncer.run_with_config(config):
        kinit()
        flags = GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG | GSS_C_DCE_STYLE
        with GssInitiator(KRB5_MECH_OID, flags) as initiator:
            assert gss_enc_login(bouncer.port, initiator) == 2
