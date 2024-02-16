import time

import pytest
from psycopg import pq

from .utils import LIBPQ_SUPPORTS_PIPELINING


def test_copy_stdin_success_simple(bouncer):
    with bouncer.conn() as conn:
        conn.pgconn.send_query(f"COPY t(i) FROM STDIN".encode())
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        conn.pgconn.put_copy_data(b"1\n")
        conn.pgconn.put_copy_end()
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None


def test_copy_stdin_error_before_copy_done_simple(bouncer):
    with bouncer.conn() as conn:
        conn.pgconn.send_query(f"COPY t(i) FROM STDIN".encode())
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
        conn.pgconn.send_query(f"COPY t(i) FROM STDIN".encode())
        assert conn.pgconn.get_result().status == pq.ExecStatus.COPY_IN
        # Send bad row
        conn.pgconn.put_copy_data(b"\n")
        conn.pgconn.put_copy_end()
        assert conn.pgconn.get_result().status == pq.ExecStatus.FATAL_ERROR
        assert conn.pgconn.get_result() is None


def test_copy_stdout_simple(bouncer):
    bouncer.sql("TRUNCATE t")
    bouncer.sql("INSERT INTO t VALUES (1), (2)")

    with bouncer.conn() as conn:
        conn.pgconn.send_query(
            f"COPY (SELECT i FROM t ORDER BY i) TO STDOUT (FORMAT TEXT)".encode()
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
        conn.pgconn.send_query_params(f"COPY t(i) FROM STDIN".encode(), [])
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
        conn.pgconn.send_query_params(f"COPY t(i) FROM STDIN".encode(), [])
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
        conn.pgconn.send_query_params(f"COPY t(i) FROM STDIN".encode(), [])
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
    bouncer.sql("TRUNCATE t")
    bouncer.sql("INSERT INTO t VALUES (1), (2)")

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_query_params(
            f"COPY (SELECT i FROM t ORDER BY i) TO STDOUT (FORMAT TEXT)".encode(), []
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


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_copy_stdin_success_prepared(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_prepare(b"p1", f"COPY t(i) FROM STDIN".encode())
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
        conn.pgconn.send_prepare(b"p1", f"COPY t(i) FROM STDIN".encode())
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
        conn.pgconn.send_prepare(b"p1", f"COPY t(i) FROM STDIN".encode())
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

    bouncer.sql("TRUNCATE t")
    bouncer.sql("INSERT INTO t VALUES (1), (2)")

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_prepare(
            b"p1", f"COPY (SELECT i FROM t ORDER BY i) TO STDOUT (FORMAT TEXT)".encode()
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
