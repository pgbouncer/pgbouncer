import asyncio
import time

import psycopg
import pytest

from .utils import CASSERT, Bouncer

# PgBouncer relaunches a DNS request only once it is ->done (see
# src/dnslookup.c). If the in-process resolver never delivers a result for a
# request -- a hung resolution -- the request stays pending forever and the
# hostname becomes permanently unresolvable, cleared only by a restart.
# dns_resolve_timeout makes adns_per_loop() relaunch such a request.
#
# The PGB_TEST_DNS_FAULT environment variable arms a test-only hook (see
# launch_request() in src/dnslookup.c) that drops the first lookup so its callback
# never fires, reproducing the hang deterministically. That hook, like the atexit
# cleanup in main.c, is compiled only in cassert builds (--enable-cassert / meson
# -Dcassert=true), so skip this module when it is absent (e.g. release,
# macOS/Windows CI).
pytestmark = pytest.mark.skipif(
    not CASSERT,
    reason="DNS fault-injection hooks require a --enable-cassert build",
)

DNS_DB = "dns_hang_db"


async def _start_hang_bouncer(
    pg, tmp_path, monkeypatch, dns_resolve_timeout, late_stale=False
):
    # Arm the cassert-only fault-injection hooks via PGB_TEST_DNS_FAULT, which
    # PgBouncer reads once at startup (see main.c). Each test starts its own
    # PgBouncer process, so this is scoped to the instance and never affects
    # other tests.
    monkeypatch.setenv(
        "PGB_TEST_DNS_FAULT", "hang,late-stale" if late_stale else "hang"
    )
    bouncer = Bouncer(pg, tmp_path / "dns_hang")
    # The base ini ends in the [pgbouncer] section, so these settings continue
    # it; the [databases] section is added last (re-opening [pgbouncer] after a
    # [databases] section would drop the earlier [pgbouncer] settings).
    bouncer.write_ini(
        f"dns_resolve_timeout = {dns_resolve_timeout}\n"
        "query_wait_timeout = 4\n"
        "\n"
        "[databases]\n"
        # host is a name (not an IP), so the lookup goes through the in-process
        # resolver; it resolves to the test Postgres on localhost.
        f"{DNS_DB} = host=localhost port={pg.port} dbname=p0 user=bouncer\n"
    )
    await bouncer.start()
    return bouncer


async def test_hung_dns_lookup_without_resolve_timeout_never_recovers(
    pg, tmp_path, monkeypatch
):
    """Bug reproduction: with dns_resolve_timeout disabled (the default) a hung
    lookup is never relaunched, so the database stays permanently unresolvable."""
    bouncer = await _start_hang_bouncer(
        pg, tmp_path, monkeypatch, dns_resolve_timeout=0
    )
    try:
        # Every attempt fails: the lookup is pending forever and never re-issued.
        for _ in range(3):
            with pytest.raises(psycopg.OperationalError):
                bouncer.test(dbname=DNS_DB)

        log = bouncer.log_path.read_text()
        assert "simulate a hung resolution" in log  # the injected hang fired
        assert "relaunching" not in log  # and was never relaunched
    finally:
        await bouncer.cleanup()


async def test_hung_dns_lookup_recovers_with_resolve_timeout(pg, tmp_path, monkeypatch):
    """Fix: with dns_resolve_timeout set, the hung lookup is relaunched and the
    database becomes resolvable again without restarting PgBouncer."""
    bouncer = await _start_hang_bouncer(
        pg, tmp_path, monkeypatch, dns_resolve_timeout=1
    )
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                bouncer.test(dbname=DNS_DB)
                break  # recovered
            except psycopg.OperationalError:
                if time.monotonic() > deadline:
                    raise
                await asyncio.sleep(0.5)

        log = bouncer.log_path.read_text()
        assert "simulate a hung resolution" in log
        assert "relaunching" in log
    finally:
        await bouncer.cleanup()


async def test_late_stale_callback_does_not_clobber_recovered_result(
    pg, tmp_path, monkeypatch
):
    """After a relaunch recovers the hostname, the original ("hung") query's late
    answer must be discarded (epoch guard in got_result_gai) so it cannot clobber
    the fresh result. The late-stale fault injects that late callback once the
    request has recovered; the database must keep resolving afterward."""
    bouncer = await _start_hang_bouncer(
        pg, tmp_path, monkeypatch, dns_resolve_timeout=1, late_stale=True
    )
    try:
        # Wait for the relaunch to recover the hostname.
        deadline = time.monotonic() + 15
        while True:
            try:
                bouncer.test(dbname=DNS_DB)
                break
            except psycopg.OperationalError:
                if time.monotonic() > deadline:
                    raise
                await asyncio.sleep(0.5)

        # The late stale callback fires on a following loop iteration.
        deadline = time.monotonic() + 5
        while "delivering late stale callback" not in bouncer.log_path.read_text():
            if time.monotonic() > deadline:
                raise AssertionError("late stale callback was not injected")
            await asyncio.sleep(0.25)

        # The fresh result survives: the database keeps resolving, and the stale
        # answer was discarded rather than processed as a lookup failure.
        for _ in range(3):
            bouncer.test(dbname=DNS_DB)
        # Without the guard the stale answer (result=0, no addrinfo) would be
        # processed as a failed lookup of the host; the guard discards it.
        log = bouncer.log_path.read_text()
        assert "DNS lookup failed: localhost" not in log
    finally:
        await bouncer.cleanup()
