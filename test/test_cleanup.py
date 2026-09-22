import psycopg
import pytest

# Runs a scenario with cleanup off and on; `cleanup` drives both the config
# and the expected outcome (leaks without the feature, cleaned with it).
cleanup_off_and_on = pytest.mark.parametrize(
    "cleanup", [False, True], ids=["off", "on"]
)


def cleanup_config(bouncer, pg, enabled, extra="", verbose=1, pool_mode="transaction"):
    return f"""
    [databases]
    postgres = host={pg.host} port={pg.port} pool_size=1

    [pgbouncer]
    listen_addr = {bouncer.host}
    auth_type = trust
    admin_users = pgbouncer
    auth_file = {bouncer.auth_path}
    listen_port = {bouncer.port}
    logfile = {bouncer.log_path}
    auth_dbname = postgres
    pool_mode = {pool_mode}
    cleanup_server_connections = {enabled}
    verbose = {verbose}
    {extra}
    """


def cleanup_log(set=r"\d", prepare=r"\d", session_authorization=r"\d"):
    return (
        r"cleaning client-altered session state "
        rf"\(set={set}, prepare={prepare}, session_authorization={session_authorization}\)"
    )


def cleanup_config_value(bouncer):
    return next(
        row[1]
        for row in bouncer.admin("SHOW CONFIG")
        if row[0] == "cleanup_server_connections"
    )


@cleanup_off_and_on
@pytest.mark.parametrize("pool_mode", ["transaction", "statement"])
def test_cleanup_set_read_only(bouncer, pg, cleanup, pool_mode):
    config = cleanup_config(bouncer, pg, enabled=int(cleanup), pool_mode=pool_mode)
    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            pid_a = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]
            cur.execute("SET default_transaction_read_only = on")

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            value = cur.execute("SHOW default_transaction_read_only").fetchall()[0][0]
            pid_b = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        assert pid_b == pid_a  # same server connection either way
        assert value == ("off" if cleanup else "on")


def test_cleanup_tracked_set_and_internal_sync(bouncer, pg):
    """An explicit client SET of a tracked parameter schedules exactly one cleanup; neither the startup parameter nor the checkout-time varcache re-apply adds a cleanup of its own (times=1 across the session)."""
    config = cleanup_config(bouncer, pg, enabled=1)
    with bouncer.run_with_config(config):
        conn = bouncer.conn(
            dbname="postgres",
            user="puser1",
            application_name="cleanup_startup",
            autocommit=True,
        )
        try:
            cur = conn.cursor()
            with bouncer.log_contains(
                cleanup_log(set=1, prepare=0, session_authorization=0),
                times=1,
            ):
                application_name, pid_a = cur.execute(
                    "SELECT current_setting('application_name'), pg_backend_pid()"
                ).fetchone()
                assert application_name == "cleanup_startup"

                cur.execute("SET application_name = 'cleanup_explicit'")

                application_name, pid_b = cur.execute(
                    "SELECT current_setting('application_name'), pg_backend_pid()"
                ).fetchone()
        finally:
            conn.close()

        assert pid_b == pid_a
        assert application_name == "cleanup_explicit"


@cleanup_off_and_on
def test_cleanup_set_role(bouncer, pg, cleanup):
    config = cleanup_config(bouncer, pg, enabled=int(cleanup))
    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="postgres") as cur:
            pid_a = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]
            cur.execute("SET ROLE puser1")

        with bouncer.cur(dbname="postgres", user="postgres") as cur:
            current_user = cur.execute("SELECT current_user").fetchall()[0][0]
            pid_b = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        assert pid_b == pid_a
        assert current_user == ("postgres" if cleanup else "puser1")


@cleanup_off_and_on
def test_cleanup_session_authorization(bouncer, pg, cleanup):
    config = cleanup_config(bouncer, pg, enabled=int(cleanup))
    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="postgres") as cur:
            pid_a = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]
            cur.execute("SET SESSION AUTHORIZATION puser1")

        with bouncer.cur(dbname="postgres", user="postgres") as cur:
            session_user = cur.execute("SELECT session_user").fetchall()[0][0]
            pid_b = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        assert pid_b == pid_a
        assert session_user == ("postgres" if cleanup else "puser1")


def test_cleanup_set_role_with_tracked_is_superuser(bouncer, pg):
    """SET ROLE must be cleaned even when is_superuser is tracked."""
    config = cleanup_config(
        bouncer,
        pg,
        enabled=1,
        extra="track_extra_parameters = is_superuser",
    )
    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="postgres") as cur:
            pid_a = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]
            with bouncer.log_contains(
                cleanup_log(set=1, prepare=0, session_authorization=0),
                times=1,
            ):
                cur.execute("SET ROLE puser1")
                cur.execute("SELECT 1")  # sequence release-time cleanup

        with bouncer.cur(dbname="postgres", user="postgres") as cur:
            current_user = cur.execute("SELECT current_user").fetchall()[0][0]
            pid_b = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        assert pid_b == pid_a
        assert current_user == "postgres"


def test_cleanup_toggle_at_runtime(bouncer, pg):
    with bouncer.run_with_config(cleanup_config(bouncer, pg, enabled=0)):
        # disabled: poison leaks
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            pid_a = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]
            cur.execute("SET default_transaction_read_only = on")
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            assert (
                cur.execute("SHOW default_transaction_read_only").fetchall()[0][0]
                == "on"
            )

        # enable via ini rewrite + RELOAD
        with bouncer.ini_path.open("w") as f:
            f.write(cleanup_config(bouncer, pg, enabled=1))
        bouncer.admin("reload")

        # next SET is detected and cleaned on release, same server conn
        with (
            bouncer.cur(dbname="postgres", user="puser1") as cur,
            bouncer.log_contains(cleanup_log(), times=1),
        ):
            cur.execute("SET default_transaction_read_only = on")
            cur.execute("SELECT 1")  # sequence the release-time cleanup
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            assert (
                cur.execute("SHOW default_transaction_read_only").fetchall()[0][0]
                == "off"
            )
            assert cur.execute("SELECT pg_backend_pid()").fetchall()[0][0] == pid_a

        # disable via admin SET: detection stops, leak returns
        bouncer.admin("set cleanup_server_connections = 0")
        with bouncer.log_contains(cleanup_log(), times=0):
            with bouncer.cur(dbname="postgres", user="puser1") as cur:
                cur.execute("SET default_transaction_read_only = on")
            with bouncer.cur(dbname="postgres", user="puser1") as cur:
                assert (
                    cur.execute("SHOW default_transaction_read_only").fetchall()[0][0]
                    == "on"
                )


def test_cleanup_superseded_by_server_reset_query_always(bouncer, pg):
    """While server_reset_query_always is on, the full reset supersedes targeted cleanup; turning it off reactivates the configured cleanup without any further action."""
    config = cleanup_config(
        bouncer,
        pg,
        enabled=1,
        extra="server_reset_query_always = 1",
    )
    with bouncer.run_with_config(config):
        # The configured value is kept; the full reset does the cleaning.
        assert cleanup_config_value(bouncer) == "1"
        with (
            bouncer.log_contains(cleanup_log(), times=0),
            bouncer.log_contains(r"resetting: DISCARD ALL"),
            bouncer.cur(dbname="postgres", user="puser1") as cur,
        ):
            cur.execute("SET default_transaction_read_only = on")
            cur.execute("SELECT 1")  # sequence the release-time reset

        # Disabling the full reset reactivates the targeted cleanup.
        bouncer.admin("SET server_reset_query_always = 0")
        with (
            bouncer.log_contains(cleanup_log(), times=1),
            bouncer.cur(dbname="postgres", user="puser1") as cur,
        ):
            cur.execute("SET default_transaction_read_only = on")
            cur.execute("SELECT 1")  # sequence the release-time cleanup
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            assert (
                cur.execute("SHOW default_transaction_read_only").fetchall()[0][0]
                == "off"
            )


def test_cleanup_independent_of_server_reset_query(bouncer, pg):
    config = cleanup_config(
        bouncer,
        pg,
        enabled=1,
        extra="server_reset_query =",
    )
    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            pid_a = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]
            cur.execute("SET default_transaction_read_only = on")

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            value = cur.execute("SHOW default_transaction_read_only").fetchall()[0][0]
            pid_b = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        assert pid_b == pid_a
        assert value == "off"


@cleanup_off_and_on
def test_cleanup_prepare(bouncer, pg, cleanup):
    config = cleanup_config(bouncer, pg, enabled=int(cleanup))
    with bouncer.run_with_config(config):
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            cur.execute("PREPARE cleanup_test AS SELECT 1")

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            if cleanup:
                cur.execute("PREPARE cleanup_test AS SELECT 1")  # name was freed
            else:
                with pytest.raises(psycopg.errors.DuplicatePreparedStatement):
                    cur.execute("PREPARE cleanup_test AS SELECT 1")


def test_cleanup_clean_connections_untouched(bouncer, pg):
    config = cleanup_config(bouncer, pg, enabled=1)
    with (
        bouncer.run_with_config(config),
        bouncer.log_contains(cleanup_log(), times=0),
    ):
        for _ in range(3):
            with bouncer.cur(dbname="postgres", user="puser1") as cur:
                cur.execute("SELECT 1")


def test_cleanup_set_local_in_transaction_cleaned(bouncer, pg):
    """SET LOCAL also schedules cleanup: the tag is indistinguishable from a non-LOCAL SET."""
    config = cleanup_config(bouncer, pg, enabled=1)
    with (
        bouncer.run_with_config(config),
        bouncer.log_contains(cleanup_log(), times=1),
    ):
        conn = bouncer.conn(dbname="postgres", user="puser1", autocommit=False)
        try:
            cur = conn.cursor()
            cur.execute("SET LOCAL statement_timeout = 7777")
            conn.commit()
        finally:
            conn.close()

        # Checkout again inside the block: sequences the cleanup and
        # verifies the setting is back at its default.
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            assert cur.execute("SHOW statement_timeout").fetchall()[0][0] == "0"


@cleanup_off_and_on
def test_cleanup_set_in_transaction(bouncer, pg, cleanup):
    config = cleanup_config(bouncer, pg, enabled=int(cleanup))
    with bouncer.run_with_config(config):
        conn = bouncer.conn(dbname="postgres", user="puser1", autocommit=False)
        try:
            cur = conn.cursor()
            cur.execute("SET statement_timeout = 7777")
            conn.commit()
        finally:
            conn.close()

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            value = cur.execute("SHOW statement_timeout").fetchall()[0][0]
        assert value == ("0" if cleanup else "7777ms")


@cleanup_off_and_on
def test_cleanup_batch_end_transaction_then_set(bouncer, pg, cleanup):
    """A SET after the transaction terminator in a single multi-statement query is outside the transaction and leaks without cleanup."""
    config = cleanup_config(bouncer, pg, enabled=int(cleanup))
    with bouncer.run_with_config(config):
        conn = bouncer.conn(dbname="postgres", user="puser1", autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("BEGIN; COMMIT; SET statement_timeout = 7777")
        finally:
            conn.close()

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            value = cur.execute("SHOW statement_timeout").fetchall()[0][0]
        assert value == ("0" if cleanup else "7777ms")


def test_cleanup_batch_set_local_in_transaction_cleaned(bouncer, pg):
    """A SET LOCAL inside a single-batch BEGIN...COMMIT still schedules cleanup; batching the transaction does not change detection."""
    config = cleanup_config(bouncer, pg, enabled=1)
    with (
        bouncer.run_with_config(config),
        bouncer.log_contains(cleanup_log(), times=1),
    ):
        conn = bouncer.conn(dbname="postgres", user="puser1", autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute("BEGIN; SET LOCAL statement_timeout = 7777; COMMIT")
        finally:
            conn.close()

        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            assert cur.execute("SHOW statement_timeout").fetchall()[0][0] == "0"


def test_cleanup_preserves_tracked_prepared_statements(bouncer, pg):
    """A SET-only cleanup (RESET ALL) must not drop tracked protocol prepared statements; a PREPARE cleanup (DEALLOCATE ALL) must clear the cache so they are re-prepared instead of erroring."""
    config = cleanup_config(
        bouncer, pg, enabled=1, extra="max_prepared_statements = 10"
    )
    with bouncer.run_with_config(config):
        conn1 = bouncer.conn(dbname="postgres", user="puser1")
        try:
            cur1 = conn1.cursor()
            # Protocol-level prepared statement, tracked by pgbouncer.
            cur1.execute("SELECT 'tracked'", prepare=True)

            # A SET cleans with RESET ROLE/ALL and no DEALLOCATE ALL; pin
            # the reset log, since transparent re-prepare would hide a wrong
            # DEALLOCATE from the execute assertion alone.
            with (
                bouncer.log_contains(r"resetting: RESET ROLE;RESET ALL;", times=1),
                bouncer.log_contains(r"DEALLOCATE ALL", times=0),
            ):
                with bouncer.cur(dbname="postgres", user="puser1") as cur2:
                    cur2.execute("SET default_transaction_read_only = on")

                # Sequences the release-time cleanup and asserts the
                # tracked statement still executes.
                assert (
                    cur1.execute("SELECT 'tracked'", prepare=True).fetchall()[0][0]
                    == "tracked"
                )

            # Another client poisons with SQL-level PREPARE; cleanup now
            # includes DEALLOCATE ALL, wiping server-side statements.
            with bouncer.cur(dbname="postgres", user="puser1") as cur2:
                cur2.execute("PREPARE cleanup_test2 AS SELECT 2")

            # cache dropped and re-prepared transparently; a stale cache
            # would error here.
            assert (
                cur1.execute("SELECT 'tracked'", prepare=True).fetchall()[0][0]
                == "tracked"
            )
        finally:
            conn1.close()

        # And the next client can reuse the SQL-level name.
        with bouncer.cur(dbname="postgres", user="puser1") as cur:
            cur.execute("PREPARE cleanup_test2 AS SELECT 2")


def test_cleanup_protocol_prepared_statement_reused_across_clients(bouncer, pg):
    config = cleanup_config(
        bouncer, pg, enabled=1, extra="max_prepared_statements = 10"
    )
    with bouncer.run_with_config(config):
        with bouncer.log_contains(cleanup_log(), times=0):
            with bouncer.cur(dbname="postgres", user="puser1") as cur:
                pid_a = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]
                assert cur.execute("SELECT 2", prepare=True).fetchall()[0][0] == 2

            with bouncer.cur(dbname="postgres", user="puser1") as cur:
                assert cur.execute("SELECT 2", prepare=True).fetchall()[0][0] == 2
                pid_b = cur.execute("SELECT pg_backend_pid()").fetchall()[0][0]

        assert pid_b == pid_a  # same server connection, not replaced
