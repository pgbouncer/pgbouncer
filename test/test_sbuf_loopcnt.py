"""
sbuf_loopcnt yield must not starve accept() or drop a write-wait.

With sbuf_loopcnt=1 every busy socket hits sbuf_wait_for_data_forced().
If that path event_assign()s an event that is still in libevent's I/O map,
the process livelocks and new connections hang.  Destination backpressure
(W_SEND) is the other failure mode: the loopcnt path must not replace the
EV_WRITE watcher with a forced EV_READ.
"""

import time


def test_sbuf_loopcnt_still_accepts(bouncer):
    bouncer.write_ini("sbuf_loopcnt = 1")
    bouncer.admin("RELOAD")

    rows = bouncer.sql("SELECT repeat('x', 200) FROM generate_series(1, 5000)")
    assert len(rows) == 5000
    assert bouncer.sql("SELECT 1")[0][0] == 1
    bouncer.admin("SHOW VERSION")


def test_sbuf_loopcnt_client_backpressure_still_accepts(bouncer):
    bouncer.write_ini("sbuf_loopcnt = 1")
    bouncer.admin("RELOAD")

    # Leave a large result unread so the client TCP window / send buffer fills
    # and sbuf_queue_send() can switch the server sbuf to W_SEND.
    stalled = bouncer.conn()
    stalled.pgconn.send_query(
        b"SELECT repeat('x', 8192) FROM generate_series(1, 20000)"
    )
    stalled.pgconn.flush()
    time.sleep(0.5)

    assert bouncer.sql("SELECT 1")[0][0] == 1
    stalled.close()
