import asyncio
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from .utils import LINUX, Bouncer

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


@pytest.fixture
async def separate_peers(pg, tmp_path):
    # Two peers that each have their own port, so that a cancel request can be
    # sent to a specific peer. Peers are reached over TCP, like they would be
    # when they run on different hosts.
    peers: dict[int, Bouncer] = {
        1: Bouncer(pg, tmp_path / "bouncer1"),
        2: Bouncer(pg, tmp_path / "bouncer2"),
    }

    for own_index, bouncer in peers.items():
        with bouncer.ini_path.open("a") as f:
            f.write(f"peer_id={own_index}\n")
            f.write("max_client_conn=200\n")
            f.write("default_pool_size=40\n")
            f.write("[peers]\n")
            for other_index, peer in peers.items():
                if own_index == other_index:
                    continue
                f.write(f"{other_index} = host=127.0.0.1 port={peer.port}\n")

    await asyncio.gather(*[p.start() for p in peers.values()])

    yield peers

    await asyncio.gather(*[p.cleanup() for p in peers.values()])


def read_exactly(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def read_message(sock):
    msg_type = read_exactly(sock, 1)
    (length,) = struct.unpack("!I", read_exactly(sock, 4))
    return msg_type, read_exactly(sock, length - 4)


def raw_connect(bouncer):
    """Connect using the raw protocol and return (socket, cancel key)"""
    sock = socket.create_connection(("127.0.0.1", bouncer.port), timeout=30)
    params = b"user\x00bouncer\x00database\x00p3\x00\x00"
    sock.sendall(struct.pack("!II", 8 + len(params), 196608) + params)
    key = None
    while True:
        msg_type, payload = read_message(sock)
        if msg_type == b"K":
            key = payload
        elif msg_type == b"Z":
            break
        elif msg_type == b"E":
            raise RuntimeError(f"login failed: {payload!r}")
    assert key is not None
    return sock, key


def send_query(sock, query):
    payload = query.encode() + b"\x00"
    sock.sendall(b"Q" + struct.pack("!I", 4 + len(payload)) + payload)


def send_cancel(bouncer, key):
    with socket.create_connection(("127.0.0.1", bouncer.port), timeout=30) as sock:
        sock.sendall(struct.pack("!II", 8 + len(key), 80877102) + key)
        # PgBouncer closes the connection once the request was handled (or
        # when it gave up on it)
        assert sock.recv(1) == b""


def query_error_code(sock):
    """Read until the query is done, return the SQLSTATE of its error (if any)"""
    code = None
    while True:
        msg_type, payload = read_message(sock)
        if msg_type == b"E":
            fields = payload.split(b"\x00")
            code = next(f[1:] for f in fields if f.startswith(b"C")).decode()
        elif msg_type == b"Z":
            return code


def test_concurrent_peer_cancel(separate_peers):
    # Cancel requests that were sent to the wrong peer have to be forwarded to
    # the right one. Only one connection attempt per peer pool is in progress
    # at a time, so when many requests arrive at once, the others should be
    # picked up afterwards instead of waiting until cancel_wait_timeout (10
    # seconds by default).
    per_peer = 12
    clients = []
    try:
        for owner in (1, 2):
            for _ in range(per_peer):
                sock, key = raw_connect(separate_peers[owner])
                clients.append((owner, sock, key))
        for _, sock, _ in clients:
            send_query(sock, "select pg_sleep(20)")
        time.sleep(1)

        # Send every cancel request to the peer that does not own the query,
        # all at the same moment.
        barrier = threading.Barrier(len(clients))

        def cancel(owner, key):
            barrier.wait()
            send_cancel(separate_peers[3 - owner], key)

        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=len(clients)) as pool:
            cancels = [pool.submit(cancel, owner, key) for owner, _, key in clients]
            for c in cancels:
                c.result()
        assert time.monotonic() - start < 5
        for _, sock, _ in clients:
            assert query_error_code(sock) == "57014"
    finally:
        for _, sock, _ in clients:
            sock.close()
