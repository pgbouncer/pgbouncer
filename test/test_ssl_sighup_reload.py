import asyncio
import socket
import ssl
import struct
import threading
import time

import pytest

from .utils import TLS_SUPPORT, WINDOWS, Bouncer

if not TLS_SUPPORT:
    pytest.skip(allow_module_level=True)

if WINDOWS:
    # SIGHUP does not exist on Windows.
    pytest.skip(allow_module_level=True)


SSL_REQUEST_CODE = 80877103


class StallingTLSBackend:
    """A fake PostgreSQL backend that accepts pgBouncer's SSLRequest, replies
    'S', and then *stalls* before completing the TLS handshake.

    The stall leaves pgBouncer parked inside SSL_connect() while it still holds
    a pointer to the server TLS config (server_connect_conf). That is the window
    in which we SIGHUP pgBouncer so the reload frees that config underneath the
    in-flight handshake (issue #1697).
    """

    def __init__(self, certfile, keyfile):
        self.certfile = str(certfile)
        self.keyfile = str(keyfile)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        # Set once the backend has sent 'S' on the first connection and is
        # about to stall -> the handshake is now in flight in pgBouncer.
        self.stalling = threading.Event()
        # The test sets this after it has sent SIGHUP, telling the backend to
        # go ahead and finish the handshake.
        self.proceed = threading.Event()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop = True
        self.proceed.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self):
        first = True
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                self._handle(conn, first)
            except (OSError, ssl.SSLError):
                pass
            first = False

    def _handle(self, conn, first):
        # Note: ssl.wrap_socket() detaches the original socket and returns a new
        # SSLSocket owning the fd, so we track the currently-live socket in
        # `sock` and close exactly that one in the finally.
        sock = conn
        try:
            hdr = _recv_exactly(sock, 8)
            if hdr is None:
                return
            _, code = struct.unpack("!II", hdr)
            if code != SSL_REQUEST_CODE:
                return
            sock.sendall(b"S")
            if first:
                # Announce the stall window and wait until the test reloaded.
                self.stalling.set()
                self.proceed.wait(timeout=10)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            sock = ctx.wrap_socket(sock, server_side=True)
            # Hold the connection open briefly so pgBouncer finishes its side of
            # the handshake (the point at which it reads the TLS config).
            time.sleep(1)
            try:
                sock.unwrap()
            except OSError:
                pass
        finally:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exactly(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _startup_packet(user, database):
    body = b"\x00\x03\x00\x00"  # protocol version 3.0
    for key, value in (("user", user), ("database", database)):
        body += key.encode() + b"\x00" + value.encode() + b"\x00"
    body += b"\x00"
    return struct.pack("!I", len(body) + 4) + body


def _trigger_backend_connection(host, port):
    """Open a client connection to pgBouncer and send a startup packet. With
    auth_type=trust this makes pgBouncer open a backend server connection and
    start the TLS handshake to our stalling fake backend."""
    cli = socket.create_connection((host, port))
    cli.sendall(_startup_packet("postgres", "stalldb"))
    return cli


async def test_sighup_during_server_tls_handshake(pg, tmp_path, cert_dir):
    """Regression test for issue #1697.

    A SIGHUP (reload) that lands while pgBouncer is in the middle of a
    server-side TLS handshake must not crash. Before the fix, the reload freed
    server_connect_conf while the in-flight handshake still pointed at it, and
    pgBouncer dereferenced the freed config (ctx->config->verify_name) when the
    handshake completed -> use-after-free / segfault.
    """
    ca = cert_dir / "TestCA1" / "ca.crt"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"

    backend = StallingTLSBackend(cert, key)
    backend.start()

    base_ini = tmp_path / "base.ini"
    base_ini.write_text(
        f"""
[databases]
stalldb = host=127.0.0.1 port={backend.port} dbname=stalldb

[pgbouncer]
listen_addr = 127.0.0.1
auth_type = trust
pool_mode = session
default_pool_size = 5
server_login_retry = 1
client_tls_protocols = all
server_tls_protocols = all
server_tls_sslmode = verify-ca
server_tls_ca_file = {ca}
"""
    )

    bouncer = Bouncer(pg, tmp_path / "bouncer", base_ini_path=base_ini)
    await bouncer.start()

    cli = None
    try:
        # Kick off a backend connection; pgBouncer begins the TLS handshake to
        # the stalling fake backend.
        cli = _trigger_backend_connection(bouncer.host, bouncer.port)

        # Wait until the backend has accepted SSL and parked pgBouncer inside
        # the handshake.
        assert backend.stalling.wait(timeout=10), (
            "pgBouncer never started the backend TLS handshake"
        )
        await asyncio.sleep(0.3)

        # Reload while the handshake is in flight. This frees server_connect_conf.
        bouncer.sighup()

        # Let the backend finish the handshake; pgBouncer now reads the TLS
        # config it just (in the buggy version) freed.
        backend.proceed.set()
        await asyncio.sleep(2)

        # pgBouncer must still be alive and responsive.
        assert bouncer.running(), (
            "pgBouncer crashed on SIGHUP during a server TLS handshake (issue #1697)"
        )
        bouncer.admin("show version")
    finally:
        if cli is not None:
            try:
                cli.close()
            except OSError:
                pass
        backend.stop()
        await bouncer.cleanup()
