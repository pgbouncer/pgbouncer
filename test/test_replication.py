import asyncio
import signal
import subprocess
import time

import psycopg
import psycopg.errors
import pytest
from psycopg import sql

from .utils import PG_MAJOR_VERSION, WINDOWS, run


def test_logical_rep(bouncer):
    connect_args = {
        "dbname": "user_passthrough",
        "replication": "database",
        "user": "postgres",
        "application_name": "abc",
        "options": "-c enable_seqscan=off",
    }
    # Starting in PG10 you can do other commands over logical rep connections
    if PG_MAJOR_VERSION >= 10:
        bouncer.test(**connect_args)
        assert bouncer.sql_value("SHOW application_name", **connect_args) == "abc"
        assert bouncer.sql_value("SHOW enable_seqscan", **connect_args) == "off"
    bouncer.sql("IDENTIFY_SYSTEM", **connect_args)
    # Do a normal connection to the same pool, to ensure that that doesn't
    # break anything
    bouncer.test(dbname="user_passthrough", user="postgres")
    bouncer.sql("IDENTIFY_SYSTEM", **connect_args)


def test_logical_rep_auth_query(bouncer):
    connect_args = {
        "dbname": "pauthz",
        "replication": "database",
        "user": "pswcheck_not_in_auth_file",
        "application_name": "abc",
        "options": "-c enable_seqscan=off",
    }
    # Starting in PG10 you can do other commands over logical rep connections
    if PG_MAJOR_VERSION >= 10:
        bouncer.test(**connect_args)
        assert bouncer.sql_value("SHOW application_name", **connect_args) == "abc"
        assert bouncer.sql_value("SHOW enable_seqscan", **connect_args) == "off"
    bouncer.sql("IDENTIFY_SYSTEM", **connect_args)
    # Do a normal connection to the same pool, to ensure that that doesn't
    # break anything
    bouncer.test(dbname="user_passthrough", user="postgres")
    bouncer.sql("IDENTIFY_SYSTEM", **connect_args)


def test_logical_rep_unprivileged(bouncer):
    if PG_MAJOR_VERSION < 10:
        expected_log = "no pg_hba.conf entry for replication connection"
    elif PG_MAJOR_VERSION < 16:
        expected_log = "must be superuser or replication role to start walsender"
    else:
        expected_log = "permission denied to start WAL sender"

    with bouncer.log_contains(
        expected_log,
    ), bouncer.log_contains(
        r"closing because: login failed \(age", times=2
    ), pytest.raises(psycopg.OperationalError, match=r"login failed"):
        bouncer.sql("IDENTIFY_SYSTEM", replication="database")


@pytest.mark.skipif(
    "PG_MAJOR_VERSION < 10", reason="logical replication was introduced in PG10"
)
def test_logical_rep_subscriber(bouncer):
    bouncer.admin("set pool_mode=transaction")

    # First write create a table and insert a row in the source database.
    # Also create the replication slot and publication
    bouncer.default_db = "user_passthrough"
    bouncer.create_schema("test_logical_rep_subscriber")
    bouncer.sql("CREATE TABLE test_logical_rep_subscriber.table(a int)")
    bouncer.sql("INSERT INTO test_logical_rep_subscriber.table values (1)")
    assert (
        bouncer.sql_value("SELECT count(*) FROM test_logical_rep_subscriber.table") == 1
    )

    bouncer.create_publication(
        "mypub", sql.SQL("FOR TABLE test_logical_rep_subscriber.table")
    )

    bouncer.create_logical_replication_slot("test_logical_rep_subscriber", "pgoutput")

    # Create an equivalent, but empty schema in the target database.
    # And setup the subscription
    bouncer.default_db = "user_passthrough2"
    bouncer.create_schema("test_logical_rep_subscriber")
    bouncer.sql("CREATE TABLE test_logical_rep_subscriber.table(a int)")
    conninfo = bouncer.make_conninfo(dbname="user_passthrough")
    bouncer.create_subscription(
        "mysub",
        sql.SQL("""
            CONNECTION {}
            PUBLICATION mypub
            WITH (slot_name=test_logical_rep_subscriber, create_slot=false)
        """).format(sql.Literal(conninfo)),
    )

    # The initial copy should now copy over the row
    time.sleep(2)
    assert (
        bouncer.sql_value("SELECT count(*) FROM test_logical_rep_subscriber.table") >= 1
    )

    # Insert another row and logical replication should replicate it correctly
    bouncer.sql(
        "INSERT INTO test_logical_rep_subscriber.table values (2)",
        dbname="user_passthrough",
    )
    time.sleep(2)
    assert (
        bouncer.sql_value("SELECT count(*) FROM test_logical_rep_subscriber.table") >= 2
    )


@pytest.mark.skipif(
    "WINDOWS", reason="MINGW does not have contrib package containing test_decoding"
)
def test_logical_rep_pg_recvlogical(bouncer):
    bouncer.default_db = "user_passthrough"
    bouncer.create_schema("test_logical_rep_pg_recvlogical")
    bouncer.sql("CREATE TABLE test_logical_rep_pg_recvlogical.table(a int)")
    bouncer.create_logical_replication_slot(
        "test_logical_rep_pg_recvlogical", "test_decoding"
    )
    process = subprocess.Popen(
        [
            "pg_recvlogical",
            "--dbname",
            bouncer.default_db,
            "--host",
            bouncer.host,
            "--port",
            str(bouncer.port),
            "--user",
            bouncer.default_user,
            "--slot=test_logical_rep_pg_recvlogical",
            "--file=-",
            "--no-loop",
            "--start",
        ],
        stdout=subprocess.PIPE,
    )
    assert process.stdout is not None
    bouncer.sql("INSERT INTO test_logical_rep_pg_recvlogical.table values (1)")
    try:
        assert process.stdout.readline().startswith(b"BEGIN ")
        assert (
            process.stdout.readline()
            == b'table test_logical_rep_pg_recvlogical."table": INSERT: a[integer]:1\n'
        )
        assert process.stdout.readline().startswith(b"COMMIT ")
    finally:
        process.kill()
        process.communicate(timeout=5)


def test_physical_rep(bouncer):
    connect_args = {
        "dbname": "user_passthrough",
        "replication": "yes",
        "user": "postgres",
        "application_name": "abc",
        "options": "-c enable_seqscan=off",
    }
    # Starting in PG10 you can do SHOW commands
    if PG_MAJOR_VERSION >= 10:
        with pytest.raises(
            psycopg.errors.FeatureNotSupported,
            match="cannot execute SQL commands in WAL sender for physical replication",
        ):
            bouncer.test(**connect_args)
        assert bouncer.sql_value("SHOW application_name", **connect_args) == "abc"
        assert bouncer.sql_value("SHOW enable_seqscan", **connect_args) == "off"
    bouncer.sql("IDENTIFY_SYSTEM", **connect_args)
    # Do a normal connection to the same pool, to ensure that that doesn't
    # break anything
    bouncer.test(dbname="user_passthrough", user="postgres")
    bouncer.sql("IDENTIFY_SYSTEM", **connect_args)


def test_physcal_rep_unprivileged(bouncer):
    with bouncer.log_contains(
        r"no pg_hba.conf entry for replication connection from host"
    ), bouncer.log_contains(
        r"closing because: login failed \(age", times=2
    ), pytest.raises(
        psycopg.OperationalError, match=r"login failed"
    ):
        bouncer.test(replication="yes")


@pytest.mark.skipif("PG_MAJOR_VERSION < 10", reason="pg_receivewal was added in PG10")
def test_physical_rep_pg_receivewal(bouncer, tmp_path):
    bouncer.default_db = "user_passthrough"
    bouncer.create_physical_replication_slot("test_physical_rep_pg_receivewal")
    wal_dump_dir = tmp_path / "wal-dump"
    wal_dump_dir.mkdir()

    process = subprocess.Popen(
        [
            "pg_receivewal",
            "--dbname",
            bouncer.make_conninfo(),
            "--slot=test_physical_rep_pg_receivewal",
            "--directory",
            str(wal_dump_dir),
        ],
    )
    time.sleep(3)

    if WINDOWS:
        process.terminate()
    else:
        process.send_signal(signal.SIGINT)
    process.communicate(timeout=5)

    if WINDOWS:
        assert process.returncode == 1
    else:
        assert process.returncode == 0

    children = list(wal_dump_dir.iterdir())
    assert len(children) > 0


def test_physical_rep_pg_basebackup(bouncer, tmp_path):
    bouncer.default_db = "user_passthrough"
    dump_dir = tmp_path / "db-dump"
    dump_dir.mkdir()

    run(
        [
            "pg_basebackup",
            "--dbname",
            bouncer.make_conninfo(),
            "--checkpoint=fast",
            "--pgdata",
            dump_dir,
        ],
    )
    children = list(dump_dir.iterdir())
    assert len(children) > 0
    print(children)


@pytest.mark.skipif(
    "PG_MAJOR_VERSION < 10",
    reason="normal SQL commands are only supported in PG10+ on logical replication connections",
)
async def test_replication_pool_size(pg, bouncer):
    thread_number = bouncer.get_thread_number()
    connect_args = {
        "dbname": "user_passthrough_pool_size2",
        "replication": "database",
        "user": "postgres",
        "connect_timeout": 10,
    }
    start = time.time()
    await bouncer.asleep(0.5, times=10, **connect_args)
    assert time.time() - start > 2.5 / thread_number
    # Replication connections always get closed right away
    assert pg.connection_count("p0") == 0

    connect_args["dbname"] = "user_passthrough_pool_size5"
    start = time.time()
    await bouncer.asleep(0.5, times=10, **connect_args)
    assert time.time() - start > 1.0 / thread_number
    # Replication connections always get closed right away
    assert pg.connection_count("p0") == 0


@pytest.mark.skipif(
    "PG_MAJOR_VERSION < 10",
    reason="normal SQL commands are only supported in PG10+ on logical replication connections",
)
async def test_replication_pool_size_mixed_clients(bouncer):
    connect_args = {
        "dbname": "user_passthrough_pool_size2",
        "user": "postgres",
    }

    # Fill the pool with normal connections
    # In multithread mode, each thread has its own pool, so we need
    # thread_number * pool_size connections to fill all pools
    thread_number = bouncer.get_thread_number()
    pool_size = 2
    num_connections = thread_number * pool_size
    await bouncer.asleep(0.5, times=num_connections, **connect_args)

    # Then try to open a replication connection and ensure that it causes
    # eviction of one of the normal connections
    with bouncer.log_contains("closing because: evicted"):
        bouncer.test(**connect_args, replication="database")
