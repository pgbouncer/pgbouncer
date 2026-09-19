"""
sbuf_loopcnt yield must not starve accept() or drop a write-wait.

With sbuf_loopcnt=1 every busy socket hits sbuf_wait_for_data_forced().
If that path event_assign()s an event that is still in libevent's I/O map,
the process livelocks and new connections hang.  Destination backpressure
(W_SEND) is the other failure mode: the loopcnt path must not replace the
EV_WRITE watcher with a forced EV_READ.
"""

import time

import pytest

from .utils import WINDOWS


def test_sbuf_loopcnt_still_accepts(bouncer):
    bouncer.write_ini("sbuf_loopcnt = 1")
    bouncer.admin("RELOAD")

    rows = bouncer.sql("SELECT repeat('x', 200) FROM generate_series(1, 5000)")
    assert len(rows) == 5000
    assert bouncer.sql_value("SELECT 1", connect_timeout=3) == 1
    bouncer.admin("SHOW VERSION")


@pytest.mark.skipif(
    "WINDOWS",
    reason=(
        "Leaving an unread result and then close() can block in libpq. "
        "pytest-timeout then kills the xdist worker, and execnet flush "
        "fails with EINVAL instead of reporting a test timeout. "
        "Win32 also ignores test.ini tcp_socket_buffer=4096."
    ),
)
def test_sbuf_loopcnt_client_backpressure_still_accepts(bouncer):
    bouncer.write_ini("sbuf_loopcnt = 1")
    bouncer.admin("RELOAD")

    # A few 8KiB rows is enough to fill test.ini's tcp_socket_buffer=4096
    # and push the client sbuf into W_SEND waiting for client sock readability.
    # leave tens of MB unread:
    # Connection.close() would then block in libpq draining the socket.
    stalled = bouncer.conn()
    try:
        stalled.pgconn.send_query(
            b"SELECT repeat('x', 8192) FROM generate_series(1, 32)"
        )
        stalled.pgconn.flush()
        time.sleep(0.5)
        assert bouncer.sql_value("SELECT 1", connect_timeout=3) == 1
    finally:
        stalled.close()
