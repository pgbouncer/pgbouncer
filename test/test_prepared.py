import random
import time

import psycopg
import pytest
from psycopg import pq, sql

from .utils import LIBPQ_SUPPORTS_PIPELINING, LINUX, USE_SUDO

PKT_BUF_SIZE = 4096


def test_prepared_statement(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set max_prepared_statements=100")
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
    bouncer.admin(f"set max_prepared_statements=100")
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


def test_deallocate_all(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set max_prepared_statements=100")
    prepared_query = "SELECT 1"
    with bouncer.cur() as cur1:
        with bouncer.cur() as cur2:
            # prepare query on client 1
            cur1.execute(prepared_query, prepare=True)
            # Run the prepared query again on same server and client
            cur1.execute(prepared_query)

            # prepared query for client 2
            cur2.execute(prepared_query, prepare=True)

            # execute DEALLOCATE ALL on client 1
            cur1.execute("DEALLOCATE ALL")

            # Run the prepared query again on server 2 and client 2
            cur2.execute(prepared_query)

            # Confirm that the prepared query is not available anymore on
            # client 1
            with bouncer.log_contains("prepared statement did not exist"):
                with pytest.raises(
                    psycopg.OperationalError,
                    match="prepared statement did not exist|server closed the connection unexpectedly",
                ):
                    cur1.execute(prepared_query)


def test_discard_all(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set max_prepared_statements=100")
    prepared_query = "SELECT 1"
    with bouncer.cur() as cur1:
        with bouncer.cur() as cur2:
            # prepare query on client 1
            cur1.execute(prepared_query, prepare=True)
            # Run the prepared query again on same server and client
            cur1.execute(prepared_query)

            # prepared query for client 2
            cur2.execute(prepared_query, prepare=True)

            # execute DISCARD ALL on client 1
            cur1.execute("DISCARD ALL")

            # Run the prepared query again on server 2 and client 2
            cur2.execute(prepared_query)

            # Confirm that the prepared query is not available anymore on
            # client 1
            with bouncer.log_contains("prepared statement did not exist"):
                with pytest.raises(
                    psycopg.OperationalError,
                    match="prepared statement did not exist|server closed the connection unexpectedly",
                ):
                    cur1.execute(prepared_query)


def test_parse_larger_than_pkt_buf(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")
    long_string = "1" * PKT_BUF_SIZE * 10
    prepared_query = "SELECT '" + long_string + "'"
    with bouncer.cur() as cur1:
        result = cur1.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == long_string


def test_bind_larger_than_pkt_buf(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")
    long_string = "1" * PKT_BUF_SIZE * 10
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
    bouncer.admin(f"set max_prepared_statements=100")
    long_string = "1" * PKT_BUF_SIZE * 2
    prepared_query = "SELECT '" + long_string + "'"
    with bouncer.cur() as cur1:
        result = cur1.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == long_string


def test_bind_larger_than_pkt_buf_but_smaller_than_4x(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")
    long_string = "1" * PKT_BUF_SIZE * 2
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
    bouncer.admin(f"set max_prepared_statements=100")
    long_string = "1" * PKT_BUF_SIZE * 10
    prepared_query = "SELECT '" + long_string + "'"
    with bouncer.cur(dbname="varcache_change") as cur1:
        result = cur1.execute(prepared_query, prepare=True).fetchone()[0]
        assert result == long_string


def test_evict_statement_cache(bouncer):
    bouncer.admin(f"set max_prepared_statements=1")
    with bouncer.cur() as cur:
        for i in range(5):
            prepared_query = f"SELECT '{i}'"
            result = cur.execute(prepared_query, prepare=True).fetchone()[0]
            assert result == str(i)

        n_statements = cur.execute(
            "SELECT count(*) FROM pg_prepared_statements"
        ).fetchone()[0]
        assert n_statements == 1

        bouncer.admin(f"set max_prepared_statements=5")
        for i in range(5, 10):
            prepared_query = f"SELECT '{i}'"
            result = cur.execute(prepared_query, prepare=True).fetchone()[0]
            assert result == str(i)

        n_statements = cur.execute(
            "SELECT count(*) FROM pg_prepared_statements"
        ).fetchone()[0]
        assert n_statements == 5

        bouncer.admin(f"set max_prepared_statements=2")

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

        # Test behaviour when disabling prepared statement handling
        bouncer.admin(f"set max_prepared_statements=0")

        # Since we disabled prepared statement handling, this should now fail
        # because we forward the client its prepared statement name to the
        # server and the server doesn't know about that name.
        with pytest.raises(psycopg.errors.InvalidSqlStatementName):
            cur.execute("SELECT '10'", prepare=True)

        # While setting the cache size to 0 disables prepared statement
        # handling completely, but it doesn't clear any of existing caches.
        # Preferably we would clear the existing caches, but that's not easy to
        # implement. Right now we only evict statements from the cache when we
        # insert into a cache, and since we disabled prepared statement
        # handling we never insert into a cache.
        n_statements = cur.execute(
            "SELECT count(*) FROM pg_prepared_statements"
        ).fetchone()[0]
        assert n_statements == 2


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_evict_statement_cache_pipeline_failure(bouncer):
    bouncer.admin(f"set max_prepared_statements=1")

    with bouncer.conn() as conn:
        with conn.pipeline() as p:
            curs = [conn.cursor() for _ in range(4)]
            curs[0].execute("SELECT 1", prepare=True)
            curs[1].execute("bad query", prepare=True)
            with pytest.raises(psycopg.errors.SyntaxError):
                p.sync()
            assert curs[0].fetchall() == [(1,)]
            curs[0].execute("SELECT 1", prepare=True)
            p.sync()
            assert curs[0].fetchall() == [(1,)]


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_prepared_statement_pipeline(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

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
    max_prepared_statements = max_prepared_stmt * 2 // 3
    size_of_param = 512
    bouncer.admin(f"set max_prepared_statements={max_prepared_statements}")

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
    bouncer.admin(f"set max_prepared_statements=100")

    with bouncer.conn() as conn:
        result = conn.pgconn.describe_prepared(b"doesnotexist")
        assert result.status == pq.ExecStatus.FATAL_ERROR
        assert b"server closed the connection unexpectedly" in result.error_message


# libpq before PG17 does not support sending Close messages
@pytest.mark.skipif("psycopg.pq.version() < 170000")
def test_close_prepared_statement(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

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
    bouncer.admin(f"set max_prepared_statements=100")

    name = b"a" * PKT_BUF_SIZE * 4

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
    bouncer.admin(f"set max_prepared_statements=100")

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
    bouncer.admin(f"set max_prepared_statements=100")

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
    bouncer.admin(f"set max_prepared_statements=100")

    with bouncer.cur() as cur:
        with pytest.raises(psycopg.errors.UndefinedTable):
            cur.execute("SELECT * FROM doesnotexistyet", prepare=True)
        cur.execute("CREATE TABLE doesnotexistyet (a int)")
        cur.execute("SELECT * FROM doesnotexistyet", prepare=True)
        cur.execute("DROP TABLE doesnotexistyet")


@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_prepared_failed_prepare_pipeline(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    with bouncer.conn() as conn:
        with conn.pipeline() as p, conn.cursor() as cur:
            cur.execute("SELECT 1", prepare=True)
            cur.execute("SELECT * FROM doesnotexistyet", prepare=True)
            cur.execute("SELECT 2", prepare=True)
            with pytest.raises(psycopg.errors.UndefinedTable):
                p.sync()
            cur.execute("SELECT 1", prepare=True)
            p.sync()
            cur.execute("SELECT 2", prepare=True)
            p.sync()
            cur.execute("CREATE TABLE doesnotexistyet (a int)")
            cur.execute("SELECT * FROM doesnotexistyet", prepare=True)
            p.sync()
            cur.execute("DROP TABLE doesnotexistyet")


def test_prepared_disallow_name_reuse(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    with bouncer.conn() as conn:
        result = conn.pgconn.prepare(b"test", b"SELECT 1")
        assert result.status == pq.ExecStatus.COMMAND_OK
        with bouncer.log_contains("prepared statement 'test' was already prepared"):
            result = conn.pgconn.prepare(b"test", b"SELECT 1")
            assert result.status == pq.ExecStatus.FATAL_ERROR


# This reproduces a bug that was found by running the JDBC test suite. We would
# only remove old data from the packet buffer when the amount of unparsed data
# was less than SMALL_PACKET_SIZE bytes left in the buffer. This meant that if
# we had a prepared statement larger than that it would loop ininitely. Now we
# remove old data from the buffer whenever the callback reports that it needs
# more data.
@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_pipeline_with_half_pkt_buf_prepare(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    long_string1 = "1" * (PKT_BUF_SIZE // 2)
    long_string2 = "2" * (PKT_BUF_SIZE // 2)

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        conn.pgconn.send_prepare(b"p1", f"SELECT 'a{long_string1}'".encode())
        conn.pgconn.send_prepare(b"p2", f"SELECT 'b{long_string2}'".encode())
        conn.pgconn.pipeline_sync()

        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


# This reproduces a bug that was found by running the JDBC test suite. The
# problem was that when we could not fit the entire prepare massage in pkt_buf
# anymore, but there was some data in the buffer that was not yet sent then
# PgBouncer would loop infinitely. Now we flush already parsed messages from
# the buffer, when the parsing of the next packet informs that it needs more
# data to do so.
@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_pipeline_flushes_on_full_pkt_buf(bouncer):
    bouncer.admin(f"set max_prepared_statements=100")

    query = b"SELECT 1"

    # We want to construct a Parse packet that is exactly the size of pkt_buf,
    # so we don't trigger the logic to use the callback buffering logic, but do
    # need the whole sbuf buffer to be availble. So let's calculate the exact
    # length of the statement name that we need to make this happen.
    size_type = 1  # 'P'
    size_length = 4  # int32
    size_query = len(query) + 1  # +1 for the null terminator
    size_param_count = 2  # int16
    size_non_statement_name = size_type + size_length + size_query + size_param_count

    # So now we construct a statement name that makes all this add up pkt_buf
    # (-1 for null terminator of the statement name)
    statement_name = b"p" * (PKT_BUF_SIZE - size_non_statement_name - 1)

    with bouncer.conn() as conn:
        conn.pgconn.enter_pipeline_mode()
        # First send a tiny packet to use some space in the sbuf, Flush is used
        # arbitrarily since it only takes 5 bytes
        conn.pgconn.send_flush_request()

        conn.pgconn.send_prepare(statement_name, query)
        conn.pgconn.pipeline_sync()

        assert conn.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
        assert conn.pgconn.get_result() is None
        assert conn.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
        conn.pgconn.exit_pipeline_mode()


# This resolves a bug where we would incorrectly release a server connection
# even though there were still requests in flight. This was causing a weird
# errors in Npgsql, because halfway through the second transaction its
# connection could be changed, thus removing any state such as portals.
# The following test reproduces a minimal version of this bug.
# See #714 for the initial report
@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_pause_before_last_sync(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    with bouncer.conn() as conn1, bouncer.cur() as cur2:
        conn1.pgconn.enter_pipeline_mode()
        conn1.pgconn.send_prepare(b"", b"SELECT $1::text")
        conn1.pgconn.send_query_prepared(b"", [b"a"])
        # This sync triggers a ready for query, which would release the
        # connection (before the fix).
        conn1.pgconn.pipeline_sync()
        # But not before the next commands were forwarded to the server
        # After the fix these commands cause the server to stay linked to the
        # client.
        conn1.pgconn.send_prepare(b"", b"SELECT $1::text")
        conn1.pgconn.flush()

        with cur2.connection.transaction():
            # Sleep a little bit to ensure the server would be released
            # (without the fix).
            time.sleep(2)

            # Then cur2 would claim the server connection that still had
            # commands from conn1 on it.
            cur2.execute("SELECT 1")

            # The execution of the prepared statement command would then open a
            # new connection without the expected prepared query on it
            conn1.pgconn.send_query_prepared(b"", [b"b"])
            conn1.pgconn.pipeline_sync()
            assert conn1.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
            assert conn1.pgconn.get_result() is None
            assert conn1.pgconn.get_result().status == pq.ExecStatus.TUPLES_OK
            assert conn1.pgconn.get_result() is None
            assert conn1.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC
            assert conn1.pgconn.get_result().status == pq.ExecStatus.COMMAND_OK
            assert conn1.pgconn.get_result() is None
            assert conn1.pgconn.get_result().status == pq.ExecStatus.TUPLES_OK
            assert conn1.pgconn.get_result() is None
            assert conn1.pgconn.get_result().status == pq.ExecStatus.PIPELINE_SYNC


@pytest.mark.skipif("not LINUX", reason="add_latency only supports Linux")
@pytest.mark.skipif("not USE_SUDO")
@pytest.mark.skipif("not LIBPQ_SUPPORTS_PIPELINING")
def test_prepared_statement_pipeline_latency(bouncer, pg):
    with bouncer.conn() as conn1:
        with conn1.pipeline() as p1:
            with pg.add_latency():
                start = time.time()
                num_queries = 7
                curs = [conn1.cursor() for _ in range(num_queries)]
                for i in range(num_queries):
                    curs[i].execute(f"SELECT '{i}'", prepare=True)
                p1.sync()

                # Each query takes at least 1 second due to the latency
                # introduced by the add_latency contextmanager. But because of
                # pipelining the latency the whole series of queries should be
                # a lot less.
                end = time.time()
                duration = end - start
                assert duration < num_queries

                # The results should be correct too
                for i in range(num_queries):
                    assert curs[i].fetchone()[0] == str(i)
