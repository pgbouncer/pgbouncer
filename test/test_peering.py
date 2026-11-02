import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from .utils import LINUX, TLS_SUPPORT, USE_UNIX_SOCKETS, Bouncer

if not LINUX:
    pytest.skip(allow_module_level=True, reason="peering tests require so_reuseport")


@pytest.fixture
async def peers(pg, tmp_path):
    peers: dict[int, Bouncer] = {}
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
    with peers[1].cur() as cur, ThreadPoolExecutor(max_workers=2) as pool:
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

    with peers[1].cur() as cur, ThreadPoolExecutor(max_workers=2) as pool:
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
        await asyncio.sleep(1)
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
        await asyncio.sleep(1)
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


@pytest.mark.skipif("not TLS_SUPPORT", reason="Requires TLS support")
@pytest.mark.skipif("not USE_UNIX_SOCKETS", reason="Requires unix sockets")
async def test_server_tls_direct_peer_cancel_unchanged(pg, tmp_path):
    """C4: with server_tls_direct=1, cancel forwarding to peers still works.

    Peers are plain-TCP PgBouncers, so if a peer pool wrongly took the direct
    TLS path the forwarded cancel could never be delivered. The query itself
    goes to Postgres over a unix socket, which direct TLS never applies to.
    """
    peers: dict[int, Bouncer] = {}
    peers[1] = Bouncer(pg, tmp_path / "bouncer1")
    peers[2] = Bouncer(pg, tmp_path / "bouncer2", port=peers[1].port)
    peers[3] = Bouncer(pg, tmp_path / "bouncer3", port=peers[1].port)

    for own_index, bouncer in peers.items():
        ini = bouncer.ini_path.read_text()
        ini = ini.replace(
            "[databases]\n",
            f"[databases]\npu = host=/tmp port={pg.port} dbname=p0 user=bouncer\n",
            1,
        )
        ini += "so_reuseport=1\nserver_tls_sslmode=require\nserver_tls_direct=1\n"
        ini += f"peer_id={own_index}\n[peers]\n"
        for other_index, peer in peers.items():
            if own_index != other_index:
                # Force TCP: a unix socket would never use direct TLS anyway.
                ini += f"{other_index} = host=127.0.0.1 port={peer.port}\n"
        bouncer.ini_path.write_text(ini)

    await asyncio.gather(*[p.start() for p in peers.values()])
    try:
        with (
            peers[1].cur(dbname="pu") as cur,
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            for _ in range(3):
                query = pool.submit(cur.execute, "select pg_sleep(5)")
                await asyncio.sleep(0.2)
                cancel = pool.submit(cur.connection.cancel)
                cancel.result()
                with pytest.raises(
                    psycopg.errors.QueryCanceled, match="due to user request"
                ):
                    query.result()
    finally:
        await asyncio.gather(*[p.cleanup() for p in peers.values()])
