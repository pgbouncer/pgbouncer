import random
import time

import psycopg
import pytest
from psycopg import pq, sql

from .utils import LIBPQ_SUPPORTS_PIPELINING, LINUX, USE_SUDO


def test_prepared_statement(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set prepared_statement_cache_size=100")
    prepared_query = "SELECT 1"
    with bouncer.cur() as cur1:
        with bouncer.cur() as cur2:
            # prepare query on server 1 and client 1
            cur1.execute(prepared_query, prepare=True)
            # Run the prepared query again on same server and client
            cur1.execute(prepared_query)
            with cur2.connection.transaction():
                # Claim server 1 with client 2
                cur2.execute("SELECT 2")
                # Client 1 now runs the prepared query, and it's automatically
                # prepared on server 2
                cur1.execute(prepared_query)
                # Client 2 now prepares the same query that was already
                # prepared on server 1. And PgBouncer reuses that already
                # prepared query for this different client.
                cur2.execute(prepared_query, prepare=True)


def test_prepared_statement_params(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set prepared_statement_cache_size=100")
    prepared_query = "SELECT %s"
    with bouncer.cur() as cur1:
        with bouncer.cur() as cur2:
            # prepare query on server 1 and client 1
            cur1.execute(prepared_query, params=(1,), prepare=True)
            # Run the prepared query again on same server and client
            cur1.execute(prepared_query, params=(1,))
            with cur2.connection.transaction():
                # Claim server 1 with client 2
                cur2.execute("SELECT 2")
                # Client 1 now runs the prepared query, and it's automatically
                # prepared on server 2
                cur1.execute(prepared_query, params=(1,))
                # Client 2 now prepares the same query that was already
                # prepared on server 1. And PgBouncer reuses that already
                # prepared query for this different client.
                cur2.execute(prepared_query, params=(1,), prepare=True)


def test_parse_larger_than_pkt_buf(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")
    long_string = "1" * 4096 * 10
    prepared_query = "SELECT '" + long_string + "'"
    with bouncer.cur() as cur1:
        result = cur1.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == long_string


def test_bind_larger_than_pkt_buf(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")
    long_string = "1" * 4096 * 10
    prepared_query = "SELECT %s::text"
    with bouncer.cur() as cur1:
        result = cur1.execute(
            prepared_query, params=(long_string,), prepare=True
        ).fetchone()[0]
        assert result == long_string


# The 4x larger than pkt_buf amount is special, because if the extra_packets
# buffer becomes larger than that it will be freed.
# (see sbuf_process_pending in  sbuf.c)
def test_parse_larger_than_pkt_buf_but_smaller_than_4x(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")
    long_string = "1" * 4096 * 2
    prepared_query = "SELECT '" + long_string + "'"
    with bouncer.cur() as cur1:
        result = cur1.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == long_string


def test_bind_larger_than_pkt_buf_but_smaller_than_4x(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")
    long_string = "1" * 4096 * 2
    prepared_query = "SELECT %s::text"
    with bouncer.cur() as cur1:
        result = cur1.execute(
            prepared_query, params=(long_string,), prepare=True
        ).fetchone()[0]
        assert result == long_string


# In one of the initial implementation of prepared statement support there was
# a bug, that if a varcache change was needed, then the callback would not be
# called again correctly later.
def test_parse_larger_than_pkt_buf_with_varcache_change(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")
    long_string = "1" * 4096 * 10
    prepared_query = "SELECT '" + long_string + "'"
    with bouncer.cur(dbname="varcache_change") as cur1:
        result = cur1.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == long_string


def test_evict_statement_cache(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=1")
    with bouncer.cur() as cur:
        for i in range(5):
            prepared_query = f"SELECT '{i}'"
            result = cur.execute(prepared_query, prepare=True).fetchone()[0]
            assert result == str(i)

        n_statements = cur.execute(
            "SELECT count(*) FROM pg_prepared_statements"
        ).fetchone()[0]
        assert n_statements == 1

        bouncer.admin(f"set prepared_statement_cache_size=5")
        for i in range(5, 10):
            prepared_query = f"SELECT '{i}'"
            result = cur.execute(prepared_query, prepare=True).fetchone()[0]
            assert result == str(i)

        n_statements = cur.execute(
            "SELECT count(*) FROM pg_prepared_statements"
        ).fetchone()[0]
        assert n_statements == 5

        bouncer.admin(f"set prepared_statement_cache_size=2")

        n_statements = cur.execute(
            "SELECT count(*) FROM pg_prepared_statements"
        ).fetchone()[0]
        assert n_statements == 5

        result = cur.execute("SELECT '10'", prepare=True).fetchone()[0]
        assert result == "10"

        n_statements = cur.execute(
            "SELECT count(*) FROM pg_prepared_statements"
        ).fetchone()[0]
        assert n_statements == 2


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_prepared_statement_pipeline(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")

    # Prepare query on the server connection and then disconnect again
    prepared_query = "SELECT 1"
    with bouncer.cur() as cur:
        result = cur.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == 1

    # Try with a prepared query first and a unprepared query second
    with bouncer.conn() as conn:
        with conn.pipeline():
            curs = [conn.cursor() for _ in range(4)]
            curs[0].execute("SELECT 2", prepare=True)
            curs[1].execute(prepared_query, prepare=True)
            curs[2].execute("SELECT 3")
            curs[3].execute(prepared_query, prepare=True)
            assert curs[0].fetchall() == [(2,)]
            assert curs[1].fetchall() == [(1,)]
            assert curs[2].fetchall() == [(3,)]
            assert curs[3].fetchall() == [(1,)]

    # Try with a unprepared query first and a prepared query second
    with bouncer.conn() as conn:
        with conn.pipeline(), conn.cursor() as cur:
            curs = [conn.cursor() for _ in range(4)]
            curs[0].execute("SELECT 2", prepare=True)
            curs[1].execute(prepared_query, prepare=True)
            curs[2].execute("SELECT 3")
            curs[3].execute(prepared_query, prepare=True)
            assert curs[0].fetchall() == [(2,)]
            assert curs[1].fetchall() == [(1,)]
            assert curs[2].fetchall() == [(3,)]
            assert curs[3].fetchall() == [(1,)]


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
@pytest.mark.timeout(300)
def test_prepared_statement_pipeline_stress(bouncer):
    max_pipeline_length = 10
    max_prepared_stmt = 100
    n_iterations = 100
    prepared_statement_cache_size = max_prepared_stmt * 2 // 3
    size_of_param = 512
    bouncer.admin(f"set prepared_statement_cache_size={prepared_statement_cache_size}")

    for pipeline_length in range(max_pipeline_length):
        # Try with a prepared query first and a unprepared query second
        with bouncer.conn() as conn:
            with conn.pipeline():
                curs = [conn.cursor() for _ in range(pipeline_length)]
                for _ in range(n_iterations):
                    for i in range(pipeline_length):
                        stmt_id = random.randint(1, max_prepared_stmt)
                        curs[i].execute(
                            sql.SQL("SELECT %s, %s::text as {}").format(
                                sql.Identifier(f"s{stmt_id}")
                            ),
                            params=(i, str(i).zfill(size_of_param)),
                            prepare=True,
                        )
                    for i in range(pipeline_length):
                        assert curs[i].fetchall() == [(i, str(i).zfill(size_of_param))]


def test_describe_non_existant_prepared_statement(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")

    with bouncer.conn() as conn:
        result = conn.pgconn.describe_prepared(b"doesnotexist")
        assert result.status == pq.ExecStatus.FATAL_ERROR
        assert b"server closed the connection unexpectedly" in result.error_message


# libpq before PG17 does not support sending Close messages
@pytest.mark.skipif("psycopg.pq.version() < 170000")
def test_close_prepared_statement(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")

    with bouncer.conn() as conn:
        result = conn.pgconn.prepare(b"test", b"SELECT 1")
        assert result.status == pq.ExecStatus.COMMAND_OK
        result = conn.pgconn.close_prepared(b"test")
        assert result.status == pq.ExecStatus.COMMAND_OK
        # closing a non-existant prepared statement should not raise an error
        result = conn.pgconn.close_prepared(b"test")
        assert result.status == pq.ExecStatus.COMMAND_OK
        # ensure that the prepared statement is actually closed by trying to
        # describe it.
        result = conn.pgconn.describe_prepared(b"test")
        assert result.status == pq.ExecStatus.FATAL_ERROR


def test_statement_name_longer_than_pkt_buf(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")

    name = b"a" * 4096 * 4

    with bouncer.conn() as conn:
        result = conn.pgconn.prepare(name, b"SELECT $1::text")
        assert result.status == pq.ExecStatus.COMMAND_OK
        result = conn.pgconn.describe_prepared(name)
        assert result.status == pq.ExecStatus.COMMAND_OK
        result = conn.pgconn.exec_prepared(name, (b"abc",))
        assert result.status == pq.ExecStatus.TUPLES_OK
        assert result.get_value(0, 0) == b"abc"

        if psycopg.pq.version() >= 170000:
            # libpq before PG17 does not support sending Close messages
            result = conn.pgconn.close_prepared(name)
            assert result.status == pq.ExecStatus.COMMAND_OK
            # Ensure that the close was successful
            result = conn.pgconn.describe_prepared(name)
            assert result.status == pq.ExecStatus.FATAL_ERROR


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_prepared_statement_pipeline_error(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")

    # Prepare query on the server connection and then disconnect again
    prepared_query = "SELECT 1"
    with bouncer.cur() as cur:
        result = cur.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == 1

    # Make sure queue is cleared after error
    with bouncer.conn() as conn:
        with conn.pipeline() as p, conn.cursor() as cur:
            cur.execute("SELECT aaaa")
            with pytest.raises(
                psycopg.errors.UndefinedColumn, match='column "aaaa" does not exist'
            ):
                p.sync()
            cur.execute(prepared_query, prepare=True)
            assert cur.fetchall() == [(1,)]


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_prepared_statement_pipeline_error_delayed_sync(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")

    # Prepare query on the server connection and then disconnect again
    prepared_query = "SELECT 1"
    with bouncer.cur() as cur:
        result = cur.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == 1

    # Make sure queue is fully cleared until Sync on error, even future
    # messages that have not yet been received by PgBouncer (including the Sync
    # itself)
    with bouncer.conn() as conn:
        with conn.pipeline() as p, conn.cursor() as cur:
            cur.execute("SELECT aaaa")
            time.sleep(0.1)

            with pytest.raises(
                psycopg.errors.UndefinedColumn, match='column "aaaa" does not exist'
            ):
                cur.execute("SELECT 123")

            with pytest.raises(psycopg.errors.PipelineAborted):
                cur.fetchall()

            p.sync()

            cur.execute(prepared_query, prepare=True)
            assert cur.fetchall() == [(1,)]


def test_prepared_failed_prepare(bouncer):
    bouncer.admin(f"set prepared_statement_cache_size=100")

    with bouncer.cur() as cur:
        with pytest.raises(psycopg.errors.UndefinedTable):
            cur.execute("SELECT * FROM doesnotexistyet", prepare=True)
        cur.execute("CREATE TABLE doesnotexistyet (a int)")
        cur.execute("SELECT * FROM doesnotexistyet", prepare=True)
        cur.execute("DROP TABLE doesnotexistyet")


@pytest.mark.skipif("not LINUX", reason="add_latency only supports Linux")
@pytest.mark.skipif("not USE_SUDO")
@pytest.mark.skip("currently not doing anything useful")
def test_prepared_statement_pipeline_latency(bouncer, pg):
    with pg.add_latency():
        # TODO: Add pipeling test
        bouncer.test()
