import asyncio
import platform
import time
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from .utils import USE_SUDO


def test_server_lifetime(pg, bouncer):
    bouncer.admin(f"set server_lifetime=2")

    bouncer.test()
    assert pg.connection_count() == 1
    time.sleep(3)
    assert pg.connection_count() == 0
    bouncer.test()


def test_server_lifetime_per_pool(pg, bouncer):
    bouncer.test(dbname="p9")
    assert pg.connection_count() == 1
    time.sleep(3)
    assert pg.connection_count() == 0
    bouncer.test(dbname="p9")


def test_server_idle_timeout(pg, bouncer):
    bouncer.admin(f"set server_idle_timeout=2")

    bouncer.test()
    assert pg.connection_count() == 1
    time.sleep(3)
    assert pg.connection_count() == 0
    bouncer.test()


def test_user_idle_transaction_timeout_negative(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = trust
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        pool_mode = session

        [users]
        puser1 = pool_mode=transaction idle_transaction_timeout=6
    """

    # while configured to be in statement pooling mode
    with bouncer.run_with_config(config):
        with bouncer.transaction(dbname="postgres", user="puser1") as cur:
            time.sleep(3)
            cur.execute("select 1")


def test_user_idle_transaction_timeout_override_global(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = trust
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        pool_mode = session
        idle_transaction_timeout=100000

        [users]
        puser1 = pool_mode=transaction idle_transaction_timeout=1
    """

    # while configured to be in statement pooling mode
    with bouncer.run_with_config(config):
        with bouncer.transaction(dbname="postgres", user="puser1") as cur:
            with bouncer.log_contains(r"idle transaction timeout"):
                time.sleep(3)
                with pytest.raises(
                    psycopg.OperationalError,
                    match=r"server closed the connection unexpectedly|Software caused connection abort",
                ):
                    cur.execute("select 1")


def test_user_idle_transaction_timeout(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = trust
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        pool_mode = session

        [users]
        puser1 = pool_mode=transaction idle_transaction_timeout=1
    """

    # while configured to be in statement pooling mode
    with bouncer.run_with_config(config):
        with bouncer.transaction(dbname="postgres", user="puser1") as cur:
            with bouncer.log_contains(r"idle transaction timeout"):
                time.sleep(3)
                with pytest.raises(
                    psycopg.OperationalError,
                    match=r"server closed the connection unexpectedly|Software caused connection abort",
                ):
                    cur.execute("select 1")


def test_user_query_timeout_override_global(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = trust
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        pool_mode = session
        query_timeout=100000

        [users]
        puser1 = pool_mode=statement query_timeout=1
    """

    # while configured to be in statement pooling mode
    with bouncer.run_with_config(config):
        with bouncer.log_contains(r"query timeout"):
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly",
            ):
                bouncer.sleep(5, user="puser1", dbname="postgres")


def test_user_query_timeout_negative(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = trust
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        pool_mode = session

        [users]
        puser1 = pool_mode=statement query_timeout=10
    """

    # while configured to be in statement pooling mode
    with bouncer.run_with_config(config):
        bouncer.sleep(5, user="puser1", dbname="postgres")


def test_user_query_timeout(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = trust
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        pool_mode = session

        [users]
        puser1 = pool_mode=statement query_timeout=1
    """

    # while configured to be in statement pooling mode
    with bouncer.run_with_config(config):
        with bouncer.log_contains(r"query timeout"):
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly",
            ):
                bouncer.sleep(5, user="puser1", dbname="postgres")


def test_query_timeout(bouncer):
    bouncer.admin(f"set query_timeout=1")

    with bouncer.log_contains(r"query timeout"):
        with pytest.raises(
            psycopg.OperationalError, match=r"server closed the connection unexpectedly"
        ):
            bouncer.sleep(5)


def test_user_level_idle_client_timeout_negative(bouncer):
    """Test user level client_idle_timeout correctly closes connection."""
    bouncer.admin("set pool_mode=transaction")
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        auth_type = trust
        admin_users = pgbouncer
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres
        pool_mode = session

        [users]
        puser1 = pool_mode=transaction client_idle_timeout=2
    """

    with bouncer.run_with_config(config):
        bouncer.admin("RELOAD")
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            cur.execute("SELECT 1")
            with bouncer.log_contains(r"client_idle_timeout"):
                time.sleep(3)
                with pytest.raises(
                    psycopg.OperationalError,
                    match=r"server closed the connection unexpectedly|Software caused connection abort",
                ):
                    cur.execute("SELECT 1")


def test_user_level_idle_client_timeout(bouncer):
    """Test that user level client_idle_timeout allows connection to stay open."""
    bouncer.admin("set pool_mode=transaction")
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        auth_type = trust
        admin_users = pgbouncer
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres
        pool_mode = session

        [users]
        puser1 = pool_mode=transaction client_idle_timeout=6
    """

    with bouncer.run_with_config(config):
        bouncer.admin("RELOAD")
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            cur.execute("SELECT 1")
            time.sleep(3)
            cur.execute("SELECT 1")


def test_user_level_idle_client_timeout_override(bouncer):
    """Test that user level client_idle_timeout overrides global level setting."""
    bouncer.admin("set pool_mode=transaction")
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        auth_type = trust
        admin_users = pgbouncer
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_dbname = postgres
        pool_mode = session
        client_idle_timeout=1000000

        [users]
        puser1 = pool_mode=transaction client_idle_timeout=2
    """

    with bouncer.run_with_config(config):
        bouncer.admin("RELOAD")
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            cur.execute("SELECT 1")
            with bouncer.log_contains(r"client_idle_timeout"):
                time.sleep(3)
                with pytest.raises(
                    psycopg.OperationalError,
                    match=r"server closed the connection unexpectedly|Software caused connection abort",
                ):
                    cur.execute("SELECT 1")


def test_transaction_timeout_user(bouncer):
    """
    Test user level transaction timeout.

    Note that 6 seconds was chosen in this test because
    bouncer.transaction seems to time out at lower timeout
    values for valgrind pipeline.

    Procedure:
        - Start pgbouncer with config that has
          user level transaction timeout of 6 seconds for user psuser1.
        - Start transaction with user puser1
        - Test that empty query works
        - Wait 7 seconds
        - Test that empty query raises psycopg.OperationalError
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port}

        [pgbouncer]
        listen_addr = {bouncer.host}
        admin_users = pgbouncer
        auth_type = trust
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        pool_mode = session

        [users]
        puser1 = pool_mode=transaction transaction_timeout=6
    """

    # while configured to be in statement pooling mode
    with bouncer.run_with_config(config):
        with bouncer.transaction(dbname="postgres", user="puser1") as cur:
            with bouncer.log_contains(r"transaction timeout"):
                cur.execute("")
                time.sleep(7)
                with pytest.raises(
                    psycopg.OperationalError,
                    match=r"server closed the connection unexpectedly|Software caused connection abort",
                ):
                    cur.execute("")


def test_transaction_timeout(bouncer):
    """
    Test pgbouncer level transaction timeout.

    Note that 6 seconds was chosen in this test because
    bouncer.transaction seems to time out at lower timeout
    values for valgrind pipeline.

    Procedure:
        - Set pool_mode=transaction in admin console (default is statement)
        - Set transaction_timeout=6
        - start transaction.
        - Execute empty query. Test that no error is raised
        - Wait 7 seconds
        - Execute emtpty query. Test that psycopg.OperationalError is raised
    """
    bouncer.admin("SET pool_mode=transaction")
    bouncer.admin("SET transaction_timeout=6")

    with bouncer.transaction() as cur:
        with bouncer.log_contains(r"transaction timeout"):
            cur.execute("")
            time.sleep(7)
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly|Software caused connection abort",
            ):
                cur.execute("")


def test_idle_transaction_timeout(bouncer):
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set idle_transaction_timeout=2")

    with bouncer.transaction() as cur:
        with bouncer.log_contains(r"idle transaction timeout"):
            time.sleep(3)
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly|Software caused connection abort",
            ):
                cur.execute("select 1")

    # test for GH issue #125
    with bouncer.transaction() as cur:
        cur.execute("select pg_sleep(2)").fetchone()
        time.sleep(1)
        cur.execute("select 1")


def test_client_idle_timeout(bouncer):
    bouncer.admin(f"set client_idle_timeout=2")

    with bouncer.cur() as cur:
        cur.execute("select 1")
        with bouncer.log_contains(r"client_idle_timeout"):
            time.sleep(3)
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly|Software caused connection abort",
            ):
                cur.execute("select 1")


@pytest.mark.asyncio
async def test_server_login_retry(pg, bouncer):
    bouncer.admin(f"set query_timeout=10")
    bouncer.admin(f"set server_login_retry=3")

    # Disable tls to get more consistent timings
    bouncer.admin("set server_tls_sslmode = disable")

    pg.stop()
    if platform.system() == "FreeBSD":
        # XXX: For some reason FreeBSD logs don't contain connect failed
        # For now we simply remove this check. But this warants further
        # investigation.
        await asyncio.gather(
            bouncer.atest(connect_timeout=10),
            pg.delayed_start(1),
        )
    else:
        with bouncer.log_contains("connect failed"):
            await asyncio.gather(
                bouncer.atest(connect_timeout=10),
                pg.delayed_start(1),
            )


def test_server_connect_timeout_establish(pg, bouncer):
    pg.configure("pre_auth_delay to '5s'")
    pg.reload()
    bouncer.admin("set query_timeout=3")
    bouncer.admin("set server_connect_timeout=2")
    with bouncer.log_contains(r"closing because: connect timeout"):
        with pytest.raises(psycopg.errors.OperationalError, match="query_timeout"):
            bouncer.test(connect_timeout=10)


@pytest.mark.skipif("not USE_SUDO")
def test_server_connect_timeout_drop_traffic(pg, bouncer):
    bouncer.admin("set query_timeout=3")
    bouncer.admin("set server_connect_timeout=2")
    with bouncer.log_contains(r"closing because: connect failed"):
        with pg.drop_traffic():
            with pytest.raises(psycopg.errors.OperationalError, match="query_timeout"):
                bouncer.test(connect_timeout=10)


@pytest.mark.skipif("not USE_SUDO")
@pytest.mark.skipif(
    "platform.system() != 'Linux'", reason="tcp_user_timeout is only supported on Linux"
)
def test_tcp_user_timeout(pg, bouncer):
    bouncer.admin("set tcp_user_timeout=1000")
    bouncer.admin("set query_timeout=5")
    # Make PgBouncer cache a connection to Postgres
    bouncer.test()
    # without tcp_user_timeout, you get a different error message
    # about "query timeout" instead
    with bouncer.log_contains(r"closing because: server conn crashed?"):
        with pg.reject_traffic():
            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly|Software caused connection abort",
            ):
                bouncer.test(connect_timeout=10)


@pytest.mark.skipif("not USE_SUDO")
@pytest.mark.asyncio
async def test_server_check_delay(pg, bouncer):
    bouncer.admin("set server_check_delay=2")
    bouncer.admin("set server_login_retry=3")
    bouncer.admin("set query_timeout=10")
    with pg.drop_traffic():
        time.sleep(3)
        query_task = bouncer.atest(connect_timeout=10)

        # We wait for 1 second to show that the query is blocked while traffic
        # is dropped.
        done, pending = await asyncio.wait([query_task], timeout=1)
        assert done == set()
        assert pending == {query_task}
    await query_task


@pytest.mark.skipif("not USE_SUDO")
def test_cancel_wait_timeout(pg, bouncer):
    bouncer.admin("set cancel_wait_timeout=1")
    with bouncer.cur() as cur:
        with ThreadPoolExecutor(max_workers=2) as pool:
            query = pool.submit(cur.execute, "select pg_sleep(3)")

            time.sleep(1)

            with pg.drop_traffic():
                with bouncer.log_contains(r"closing because: cancel_wait_timeout"):
                    cancel = pool.submit(cur.connection.cancel)
                    cancel.result()

            query.result()
