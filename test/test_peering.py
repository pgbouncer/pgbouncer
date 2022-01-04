import pytest
import asyncio
import time
import psycopg
from typing import Dict
from concurrent.futures import ThreadPoolExecutor
from .utils import Bouncer, LINUX

if not LINUX:
    pytest.skip(allow_module_level=True, reason='peering tests require so_reuseport')

@pytest.mark.asyncio
@pytest.fixture
async def peers(pg, tmp_path):
    peers: Dict[int, Bouncer] = {}
    peers[1] = Bouncer(pg, tmp_path / "bouncer1")

    peers[2] = Bouncer(pg, tmp_path / "bouncer2", port=peers[1].port)

    peers[3] = Bouncer(pg, tmp_path / "bouncer3", port=peers[1].port)

    for own_index, bouncer in peers.items():
        with bouncer.ini_path.open("a") as f:
            f.write('so_reuseport=1\n')
            f.write(f'peer_id={own_index}\n')
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
                time.sleep(.5)
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
        bouncer.admin('reload')

    with peers[1].cur() as cur:
        with ThreadPoolExecutor(max_workers=2) as pool:
            for _ in range(10):
                query = pool.submit(cur.execute, "select pg_sleep(5)")
                time.sleep(.5)
                cancel = pool.submit(cur.connection.cancel)
                cancel.result()
                with pytest.raises(
                    psycopg.errors.QueryCanceled, match="due to user request"
                ):
                    query.result()
