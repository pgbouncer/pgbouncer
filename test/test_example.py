import time
import pytest
import psycopg

import asyncio


def test_show(bouncer):
    show_items = [
        "clients",
        "config",
        "databases",
        # Calling show fds on MacOS leaks the returned file descriptors to the
        # python test runner. So we don't test this one directly. SHOW FDS is
        # still tested indirectly by the takeover tests.
        # "fds",
        "help",
        "lists",
        "pools",
        "servers",
        "sockets",
        "active_sockets",
        "stats",
        "stats_totals",
        "stats_averages",
        "users",
        "totals",
        "mem",
        "dns_hosts",
        "dns_zones",
    ]

    for item in show_items:
        bouncer.admin(f"SHOW {item}")


def test_server_lifetime(pg, bouncer):
    bouncer.default_db = "p0"
    bouncer.admin(f"set server_lifetime=2")

    bouncer.sql_oneshot("select now()")
    assert pg.connection_count() == 1
    time.sleep(3)
    assert pg.connection_count() == 0
    bouncer.sql("select now()")


def test_server_idle_timeout(pg, bouncer):
    bouncer.default_db = "p0"
    bouncer.admin(f"set server_idle_timeout=2")

    bouncer.sql_oneshot("select now()")
    assert pg.connection_count() == 1
    time.sleep(3)
    assert pg.connection_count() == 0
    bouncer.sql("select now()")


def test_query_timeout(bouncer):
    bouncer.default_db = "p0"
    bouncer.admin(f"set query_timeout=1")

    with bouncer.log_contains(r"query timeout"):
        with pytest.raises(psycopg.OperationalError, match=r"server closed the connection unexpectedly"):
            bouncer.sql_oneshot("select pg_sleep(5)")


def test_idle_transaction_timeout(bouncer):
    bouncer.default_db = "p0"
    bouncer.admin(f"set pool_mode=transaction")
    bouncer.admin(f"set idle_transaction_timeout=2")

    with bouncer.transaction() as cur:
        with bouncer.log_contains(r"idle transaction timeout"):
            time.sleep(3)
            with pytest.raises(psycopg.OperationalError, match=r"server closed the connection unexpectedly"):
                cur.execute("select now()")

    # test for GH issue #125
    with bouncer.transaction() as cur:
        cur.execute("select pg_sleep(2)").fetchone()
        time.sleep(1)
        cur.execute("select now()")


def test_client_idle_timeout(bouncer):
    bouncer.default_db = "p0"
    bouncer.admin(f"set client_idle_timeout=2")

    bouncer.sql("select now()")
    with bouncer.log_contains(r"client_idle_timeout"):
        time.sleep(3)
        with pytest.raises(psycopg.OperationalError, match=r"server closed the connection unexpectedly"):
            bouncer.sql("select now()")


async def test_server_login_retry(pg, bouncer):
    bouncer.default_db = "p0"
    bouncer.admin(f"set query_timeout=10")
    bouncer.admin(f"set server_login_retry=3")

    pg.stop()
    with bouncer.log_contains("connect failed"):
        await asyncio.gather(
            bouncer.asql("select now()"),
            pg.delayed_start(1),
        )
