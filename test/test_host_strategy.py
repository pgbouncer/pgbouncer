import psycopg
import pytest


@pytest.mark.asyncio
async def test_host_strategy_last_successful_good_first(bouncer):
    with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 2):
        await bouncer.asleep(dbname="hostlist_good_first", duration=0.5, times=2)


@pytest.mark.asyncio
async def test_host_strategy_last_successful_bad_first(bouncer):
    bouncer.admin(f"set server_login_retry=1")
    with bouncer.log_contains(r"closing because: server DNS lookup failed", 1):
        with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 2):
            # Execute two concurrent sleeps to force two backend connections.
            # The first connection will attempt the "bad" host and retry on
            # the "good" host.
            # The second connection will honor `host_strategy` and use the
            # `last_successful` host.
            await bouncer.asleep(dbname="hostlist_bad_first", duration=0.5, times=2)
