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
