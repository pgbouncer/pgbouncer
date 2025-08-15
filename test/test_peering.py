import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict

import psycopg
import pytest

from .utils import LINUX, Bouncer

if not LINUX:
    pytest.skip(allow_module_level=True, reason="peering tests require so_reuseport")


@pytest.fixture
async def peers(pg, tmp_path):
    peers: Dict[int, Bouncer] = {}
    peers[1] = Bouncer(pg, tmp_path / "bouncer1")

    peers[2] = Bouncer(pg, tmp_path / "bouncer2", port=peers[1].port)

    peers[3] = Bouncer(pg, tmp_path / "bouncer3", port=peers[1].port)

    for own_index, bouncer in peers.items():
        with bouncer.ini_path.open("a") as f:
            f.write("so_reuseport=1\n")
            f.write(f"peer_id={own_index}\n")
            f.write("[peers]\n")
            for other_index, peer in peers.items():
                if own_index == other_index:
                    continue
                f.write(f"{other_index} = host={peer.admin_host} port={peer.port}\n")

    await asyncio.gather(*[p.start() for p in peers.values()])

    yield peers

    await asyncio.gather(*[p.cleanup() for p in peers.values()])


def test_peering_without_own_index(peers):
    with peers[1].cur() as cur:
        with ThreadPoolExecutor(max_workers=2) as pool:
            for _ in range(10):
                query = pool.submit(cur.execute, "select pg_sleep(5)")
                time.sleep(0.5)
                cancel = pool.submit(cur.connection.cancel)
                cancel.result()
                with pytest.raises(
                    psycopg.errors.QueryCanceled, match="due to user request"
                ):
                    query.result()


def test_peering_with_own_index(peers):
    for own_index, bouncer in peers.items():
        with bouncer.ini_path.open("a") as f:
            f.write(f"{own_index} = host={bouncer.admin_host} port={bouncer.port}\n")
        bouncer.admin("reload")

    with peers[1].cur() as cur:
        with ThreadPoolExecutor(max_workers=2) as pool:
            for _ in range(10):
                query = pool.submit(cur.execute, "select pg_sleep(5)")
                time.sleep(0.5)
                cancel = pool.submit(cur.connection.cancel)
                cancel.result()
                with pytest.raises(
                    psycopg.errors.QueryCanceled, match="due to user request"
                ):
                    query.result()


async def test_rolling_restart_admin(peers):
    # Stop 2 of the 3 peers, so that we know we connect to peer 1
    await peers[2].stop()
    await peers[3].stop()
    with peers[1].cur() as cur:
        cur.execute("select 1")

        # Trigger a shutdown, but the process should keep running until we
        # close the connection
        peers[1].admin("shutdown wait_for_clients")
        time.sleep(1)
        assert peers[1].running()

        # New connection attempts are now expected to fail, because no process
        # is listening on the port. Under normal usage you would continue to
        # leave at least one running. But for testing purposes this is the
        # easiest way to show that peer[1] is not accepting new connections
        # anymore.
        with pytest.raises(psycopg.OperationalError, match="Connection refused"):
            peers[1].test()
        # But the existing connection is still be allowed to execute any
        # queries.
        cur.execute("select 1")

        await peers[2].start()

        # Now that peer[2] is running again, new connections should start
        # working too.
        peers[1].test()

    # Now that the connection is closed, peer[1] should exit automatically.
    await peers[1].wait_for_exit()
    assert not peers[1].running()


async def test_rolling_restart_sigterm(peers):
    # Stop 2 of the 3 peers, so that we know we connect to peer 1
    await peers[2].stop()
    await peers[3].stop()
    with peers[1].cur() as cur:
        cur.execute("select 1")

        # Trigger a shutdown, but the process should keep running until we
        # close the connection
        peers[1].sigterm()
        time.sleep(1)
        assert peers[1].running()

        # New connection attempts are now expected to fail, because no process
        # is listening on the port. Under normal usage you would continue to
        # leave at least one running. But for testing purposes this is the
        # easiest way to show that peer[1] is not accepting new connections
        # anymore.
        with pytest.raises(psycopg.OperationalError, match="Connection refused"):
            peers[1].test()
        # But the existing connection is still be allowed to execute any
        # queries.
        cur.execute("select 1")

        await peers[2].start()

        # Now that peer[2] is running again, new connections should start
        # working too.
        peers[1].test()

    # Now that the connection is closed, peer[1] should exit automatically.
    await peers[1].wait_for_exit()
    assert not peers[1].running()
