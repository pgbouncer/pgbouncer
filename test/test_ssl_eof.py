import socket
import ssl
import struct
import time

import pytest

from .utils import TEST_DIR, TLS_SUPPORT, WINDOWS, Bouncer

if not TLS_SUPPORT:
    pytest.skip(allow_module_level=True)

if WINDOWS:
    pytest.skip(allow_module_level=True)


@pytest.fixture
async def bouncer(pg, tmp_path):
    bouncer = Bouncer(
        pg, tmp_path / "bouncer", base_ini_path=TEST_DIR / "ssl" / "test.ini"
    )
    await bouncer.start()
    yield bouncer
    await bouncer.cleanup()


def _abrupt_tls_close(host, port, ca_file):
    """Open a TLS connection through pgBouncer's TLS startup, finish the
    handshake, then close the TCP socket without a TLS close_notify alert.
    """
    sock = socket.create_connection((host, port))
    try:
        # PostgreSQL SSLRequest: 4-byte length=8, 4-byte code=80877103
        sock.sendall(struct.pack("!II", 8, 80877103))
        resp = sock.recv(1)
        assert resp == b"S", f"expected 'S' SSLResponse, got {resp!r}"

        ctx = ssl.create_default_context(cafile=str(ca_file))
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname="localhost")
        # SSLSocket.close() does not send close_notify (only unwrap() does),
        # so this drops the connection abruptly from pgBouncer's perspective.
        tls.close()
    finally:
        try:
            sock.close()
        except OSError:
            pass


def test_no_unexpected_eof_warning(bouncer, cert_dir):
    """Regression test for the OpenSSL 3 "unexpected eof while reading"
    warning. When a TLS client closes the TCP connection without sending a
    close_notify alert, OpenSSL 3 reports SSL_R_UNEXPECTED_EOF_WHILE_READING
    via SSL_ERROR_SSL. pgBouncer must treat that as a clean EOF (same as
    the pre-3.0 SSL_ERROR_SYSCALL+ret==0 path) rather than logging a noisy
    WARNING for every disconnect.
    """
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.admin(f"set client_tls_key_file = '{key}'")
    bouncer.admin(f"set client_tls_cert_file = '{cert}'")
    bouncer.admin(f"set client_tls_ca_file = '{root}'")
    bouncer.admin(f"set client_tls_sslmode = require")

    with bouncer.log_contains(r"unexpected eof while reading", times=0):
        _abrupt_tls_close("localhost", bouncer.port, root)
        # Give pgBouncer a moment to observe the EOF on the read side and
        # write anything it would write to the log.
        time.sleep(1)
