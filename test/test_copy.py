import socket
import struct
import time

import pytest
from psycopg import pq

from .utils import LIBPQ_SUPPORTS_PIPELINING


def test_copy_stdin_success_simple(bouncer):
    with bouncer.conn() as conn:
        conn.pgconn.send_query(f"COPY test_copy(i) FROM STDIN".encode())
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_data(b"1\n")
        conn.pgconn.put_copy_end()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None


def test_copy_stdin_error_before_copy_done_simple(bouncer):
    with bouncer.conn() as conn:
        conn.pgconn.send_query(f"COPY test_copy(i) FROM STDIN".encode())
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        # Flush and wait a bit so PgBouncer can receive the error
        conn.pgconn.flush()
        time.sleep(1)
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_end()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None


def test_copy_stdin_error_after_copy_done_simple(bouncer):
    with bouncer.conn() as conn:
        conn.pgconn.send_query(f"COPY test_copy(i) FROM STDIN".encode())
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        conn.pgconn.put_copy_end()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None


def test_copy_stdout_simple(bouncer):
    bouncer.sql("TRUNCATE test_copy")
    bouncer.sql("INSERT INTO test_copy VALUES (1), (2)")

    with bouncer.conn() as conn:
        conn.pgconn.send_query(
            f"COPY (SELECT i FROM test_copy ORDER BY i) TO STDOUT (FORMAT TEXT)".encode()
        )
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_OUT

        assert conn.pgconn.get_copy_data(0) == (2, b"1\n")
        assert conn.pgconn.get_copy_data(0) == (2, b"2\n")
        assert conn.pgconn.get_copy_data(0) == (-1, b"")
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdin_success_extended(bouncer):
    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_query_params(f"COPY test_copy(i) FROM STDIN".encode(), [])
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_data(b"1\n")
        conn.pgconn.put_copy_end()
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdin_error_before_copy_done_extended(bouncer):
    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_query_params(f"COPY test_copy(i) FROM STDIN".encode(), [])
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        # Flush and wait a bit so PgBouncer can receive the error
        conn.pgconn.flush()
        time.sleep(1)
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_end()
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdin_error_after_copy_done_extended(bouncer):
    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_query_params(f"COPY test_copy(i) FROM STDIN".encode(), [])
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        conn.pgconn.put_copy_end()
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdout_extended(bouncer):
    bouncer.sql("TRUNCATE test_copy")
    bouncer.sql("INSERT INTO test_copy VALUES (1), (2)")

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_query_params(
            f"COPY (SELECT i FROM test_copy ORDER BY i) TO STDOUT (FORMAT TEXT)".encode(),
            [],
        )
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_OUT

        assert conn.pgconn.get_copy_data(0) == (2, b"1\n")
        assert conn.pgconn.get_copy_data(0) == (2, b"2\n")
        assert conn.pgconn.get_copy_data(0) == (-1, b"")
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


def test_copy_stdin_error_before_copy_done_transaction_pool(bouncer):
    """Late CopyDone must not create phantom outstanding request in transaction pool mode.

    When the server sends ErrorResponse + ReadyForQuery before the client
    sends CopyDone (race condition triggered by flush + sleep), the late
    CopyDone must not be tracked as an outstanding request.  Without the
    fix, the phantom CopyDone entry in outstanding_requests prevents the
    server from ever being released: pop_outstanding_request in the
    ReadyForQuery handler fails to match it (not Query/Sync/FunctionCall),
    so outstanding_requests never empties and the server stays linked.
    """
    bouncer.admin("set default_pool_size=1")
    bouncer.admin("set query_wait_timeout=5")

    with bouncer.conn(dbname="p3x") as conn:
        conn.pgconn.send_query(b"COPY test_copy(i) FROM STDIN")
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        # Flush and wait so PgBouncer receives ErrorResponse before CopyDone
        conn.pgconn.flush()
        time.sleep(1)
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_end()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None

        # Follow-up query triggers ReadyForQuery which should release the
        # server.  Without the fix the phantom CopyDone blocks release.
        conn.pgconn.send_query(b"SELECT 1")
        assert conn.pgconn.get_result().status == pq.ExecStatus.TUPLES_OK
        assert conn.pgconn.get_result() is None

        # With pool_size=1, if the server is stuck, this second connection
        # will fail with query_wait_timeout.
        bouncer.sql("SELECT 1", dbname="p3x")


def test_copy_stdin_error_before_copy_done_in_transaction(bouncer):
    """Late CopyDone within explicit transaction must not block server release.

    Same race condition as above, but wrapped in BEGIN/ROLLBACK.
    ReadyForQuery state 'E' keeps the server linked during the error
    transaction, then the late CopyDone arrives.  After ROLLBACK + a
    follow-up query, the server should be released.  Without the fix,
    the phantom CopyDone outstanding request prevents release.
    """
    bouncer.admin("set default_pool_size=1")
    bouncer.admin("set query_wait_timeout=5")

    with bouncer.conn(dbname="p3x") as conn:
        conn.pgconn.send_query(b"BEGIN")
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None

        conn.pgconn.send_query(b"COPY test_copy(i) FROM STDIN")
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        conn.pgconn.flush()
        time.sleep(1)
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_end()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None

        conn.pgconn.send_query(b"ROLLBACK")
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None

        # Follow-up query to trigger server release
        conn.pgconn.send_query(b"SELECT 1")
        assert conn.pgconn.get_result().status == pq.ExecStatus.TUPLES_OK
        assert conn.pgconn.get_result() is None

        # Verify server was released back to the pool
        bouncer.sql("SELECT 1", dbname="p3x")


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdin_success_prepared(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_prepare(b"p1", f"COPY test_copy(i) FROM STDIN".encode())
        conn.pgconn.send_query_prepared(b"p1", [])
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_data(b"1\n")
        conn.pgconn.put_copy_end()
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdin_error_before_copy_done_prepared(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_prepare(b"p1", f"COPY test_copy(i) FROM STDIN".encode())
        conn.pgconn.send_query_prepared(b"p1", [])
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        # Flush and wait a bit so PgBouncer can receive the error
        conn.pgconn.flush()
        time.sleep(1)
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_end()
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdin_error_after_copy_done_prepared(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_prepare(b"p1", f"COPY test_copy(i) FROM STDIN".encode())
        conn.pgconn.send_query_prepared(b"p1", [])
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        conn.pgconn.put_copy_end()
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdout_prepared(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    bouncer.sql("TRUNCATE test_copy")
    bouncer.sql("INSERT INTO test_copy VALUES (1), (2)")

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_prepare(
            b"p1",
            f"COPY (SELECT i FROM test_copy ORDER BY i) TO STDOUT (FORMAT TEXT)".encode(),
        )
        conn.pgconn.send_query_prepared(b"p1", [])
        conn.pgconn.pipeline_sync()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_OUT

        assert conn.pgconn.get_copy_data(0) == (2, b"1\n")
        assert conn.pgconn.get_copy_data(0) == (2, b"2\n")
        assert conn.pgconn.get_copy_data(0) == (-1, b"")
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


class _RawCopyClient:
    """Minimal raw v3 protocol client, used to send CopyData/CopyDone/CopyFail
    before reading CopyInResponse (the way pgx does). libpq refuses to send
    copy data in that order."""

    def __init__(self, host, port, dbname, user="postgres"):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.buf = b""
        self.error = None
        payload = (
            b"user\x00" + user.encode() + b"\x00"
            b"database\x00" + dbname.encode() + b"\x00\x00"
        )
        self.sock.sendall(
            struct.pack("!i", len(payload) + 8) + struct.pack("!i", 196608) + payload
        )
        self.wait_ready()

    def _recv_msg(self):
        while len(self.buf) < 5:
            self.buf += self.sock.recv(65536)
        typ = self.buf[0:1]
        length = struct.unpack("!i", self.buf[1:5])[0]
        while len(self.buf) < length + 1:
            self.buf += self.sock.recv(65536)
        payload = self.buf[5 : length + 1]
        self.buf = self.buf[length + 1 :]
        return typ, payload

    def wait_ready(self):
        while True:
            typ, payload = self._recv_msg()
            if typ == b"E":
                self.error = payload
            elif typ == b"Z":
                return

    @staticmethod
    def _msg(typ, payload):
        return typ + struct.pack("!i", len(payload) + 4) + payload

    def copy_from_stdin(self, table, data):
        # Query, CopyData and CopyDone in a single write, without waiting for
        # CopyInResponse (pgx v5 CopyFrom does the same).
        self.sock.sendall(
            self._msg(b"Q", b"COPY " + table + b" FROM STDIN\x00")
            + self._msg(b"d", data)
            + self._msg(b"c", b"")
        )
        self.wait_ready()

    def copy_fail(self, table, message):
        # CopyFail before CopyInResponse, same race as above.
        self.sock.sendall(
            self._msg(b"Q", b"COPY " + table + b" FROM STDIN\x00")
            + self._msg(b"f", message + b"\x00")
        )
        self.wait_ready()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def test_copy_stdin_copy_done_before_copy_in_response(bouncer):
    """A CopyDone that arrives before CopyInResponse must not pin the server.

    pgx v5 CopyFrom sends Query, CopyData and CopyDone back-to-back without
    waiting for CopyInResponse. PgBouncer then processes CopyDone before
    setting client->copy_mode from CopyInResponse, and the flag would never
    be cleared, keeping the server linked to the client until it disconnects.
    """
    bouncer.admin("set default_pool_size=1")
    bouncer.admin("set query_wait_timeout=5")

    client = _RawCopyClient("127.0.0.1", bouncer.port, "p3x")
    try:
        client.copy_from_stdin(b"test_copy(i)", b"1\n")
        assert client.error is None

        # If the server is still linked to the raw client, this second
        # connection has to wait for it and hits query_wait_timeout.
        bouncer.sql("SELECT 1", dbname="p3x")
    finally:
        client.close()


def test_copy_stdin_copy_fail_before_copy_in_response(bouncer):
    """A CopyFail that arrives before CopyInResponse must not pin the server."""
    bouncer.admin("set default_pool_size=1")
    bouncer.admin("set query_wait_timeout=5")

    client = _RawCopyClient("127.0.0.1", bouncer.port, "p3x")
    try:
        client.copy_fail(b"test_copy(i)", b"client aborted")
        assert client.error is not None

        bouncer.sql("SELECT 1", dbname="p3x")
    finally:
        client.close()


def test_copy_stdin_server_error_with_copy_done_before_copy_in_response(bouncer):
    """A server-side COPY error after an early CopyDone must not pin the server."""
    bouncer.admin("set default_pool_size=1")
    bouncer.admin("set query_wait_timeout=5")

    client = _RawCopyClient("127.0.0.1", bouncer.port, "p3x")
    try:
        client.copy_from_stdin(b"test_copy(i)", b"not-an-int\n")
        assert client.error is not None

        bouncer.sql("SELECT 1", dbname="p3x")
    finally:
        client.close()
