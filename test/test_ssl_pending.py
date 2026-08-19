"""Regression test for the lost wakeup on TLS sockets (GH #1530).

When PgBouncer needs a whole packet before it can handle it, but only part of
that packet fits in the sbuf, sbuf_process_pending() bails out and PgBouncer
waits for a read event on the socket. On a TLS connection the rest of that
packet may already have been decrypted into OpenSSL's own buffer by the
SSL_read() that filled the sbuf, leaving the kernel socket empty. The
level-triggered read event then never fires again and the connection stalls.

Postgres sends its whole login response in a single write, so a role with a
long enough search_path both pushes that response past pkt_buf and provides
the large packet across the boundary that is needed to reach this path.
"""

import pytest

from .utils import PG_MAJOR_VERSION, TEST_DIR, TLS_SUPPORT, WINDOWS, Bouncer

if not TLS_SUPPORT:
    pytest.skip(allow_module_level=True)

# The pkt_buf the bouncer_tls fixture below runs with, which is the size of a
# single sbuf and thus the offset at which PgBouncer cuts the login response in
# half. Deliberately much smaller than the 4096 default: the packet across the
# boundary has to fit in one sbuf, so a small pkt_buf keeps the search_path
# this test needs small too.
PKT_BUF = 1024

# SBUF_SMALL_PKT in include/sbuf.h. When a full buffer ends with no more than
# this many unparsed bytes, sbuf_process_pending() leaves them alone instead of
# handing a partial packet to the protocol handler, and the buffer-is-full path
# then reads again by itself. So the packet across the boundary has to be
# bigger than this to reach the path that stalls.
SBUF_SMALL_PKT = 64

# A ParameterStatus is a type byte, a 4 byte length, and the key and the value
# each terminated by a NUL.
PARAMETER_STATUS_OVERHEAD = len("search_path") + 7

# Make the search_path packet 8 bytes shorter than an sbuf. That is what lines
# it up across the boundary without having to know where in the login response
# Postgres puts it:
#
#   - it ends past the boundary as long as it starts after byte 8, and it
#     always does, because AuthenticationOk alone takes up the first 9 bytes
#   - it still fits in one sbuf, so PgBouncer takes the path that stalls
#     instead of the one that buffers oversized packets whole
#   - the rest of the login response is a few hundred bytes of small
#     ParameterStatus packets, far less than PKT_BUF - SBUF_SMALL_PKT, so the
#     part of the packet before the boundary is comfortably over SBUF_SMALL_PKT
SEARCH_PATH_LEN = PKT_BUF - 8 - PARAMETER_STATUS_OVERHEAD


@pytest.fixture
async def bouncer_tls(pg, tmp_path):
    bouncer_tls = Bouncer(
        pg, tmp_path / "bouncer", base_ini_path=TEST_DIR / "ssl" / "test.ini"
    )
    # pkt_buf cannot be changed with RELOAD, so it has to be set before start.
    bouncer_tls.write_ini(f"pkt_buf = {PKT_BUF}")
    await bouncer_tls.start()
    yield bouncer_tls
    await bouncer_tls.cleanup()


def test_tls_login_packet_across_sbuf_boundary(pg, bouncer_tls, cert_dir):
    """A packet split across the sbuf boundary must not stall a TLS connection.

    Without the SSL_pending() check the bytes after the boundary stay inside
    OpenSSL, the read event never fires again, and the server login hangs until
    server_connect_timeout kicks in.
    """
    pg.ssl_access("all", "trust")
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{cert_dir / 'TestCA1' / 'ca.crt'}'")
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()

    bouncer_tls.admin("set server_tls_sslmode = require")

    try:
        pg.sql(f"alter role bouncer set search_path = '{'a' * SEARCH_PATH_LEN}'")

        with pg.conn(dbname="p0", user="bouncer") as conn:
            reported = conn.pgconn.parameter_status(b"search_path")

        # Only newer Postgres versions mark search_path as GUC_REPORT, and
        # without a ParameterStatus for it there is no oversized packet in the
        # login response to put across the boundary.
        if reported is None:
            pytest.skip("this Postgres does not report search_path")

        # Guard against this test silently passing because Postgres reported
        # something other than the value we set, which would change the size of
        # the packet and could move it off the boundary.
        assert len(reported) == SEARCH_PATH_LEN

        # PgBouncer only answers once the server login this triggers has
        # completed, so a stalled server connection shows up as a timeout
        # rather than as a wrong answer.
        assert bouncer_tls.sql_value("select 1", connect_timeout=8) == 1
    finally:
        pg.sql("alter role bouncer reset search_path")
