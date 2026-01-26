"""Tests for load balancing with multiple hosts and ports."""

import subprocess

import psycopg
import pytest

from .utils import Bouncer, Postgres, USE_SUDO, LINUX, run, sudo


@pytest.fixture(scope="session")
def pg2(tmp_path_factory):
    """Starts a second Postgres instance."""
    pg2 = Postgres(tmp_path_factory.getbasetemp() / "pgdata2")
    pg2.initdb()
    pg2.nossl_access("all", "trust")
    pg2.commit_hba()
    pg2.start()
    pg2.sql("create database p0")
    pg2.sql("create user bouncer")
    pg2.sql("grant all on schema public to public", dbname="p0")
    yield pg2
    pg2.cleanup()


@pytest.fixture(scope="session")
def pg2_same_port(pg, tmp_path_factory):
    """Second Postgres on 127.0.0.2 using the SAME port as pg (requires sudo)."""
    if not LINUX or not USE_SUDO:
        pytest.skip("Requires Linux and USE_SUDO=1")

    # Add 127.0.0.2 loopback alias if not present
    result = subprocess.run(["ip", "addr", "show", "dev", "lo"], capture_output=True, text=True)
    if "127.0.0.2" not in result.stdout:
        sudo("ip addr add 127.0.0.2/8 dev lo")

    # Create Postgres bound to 127.0.0.2
    pg2 = Postgres(tmp_path_factory.getbasetemp() / "pgdata2_sameport")
    pg2.host = "127.0.0.2"
    pg2.initdb()

    # Configure to listen only on 127.0.0.2, disable unix socket (would conflict with pg)
    with pg2.conf_path.open(mode="a") as pgconf:
        pgconf.write("listen_addresses='127.0.0.2'\n")
        pgconf.write("unix_socket_directories=''\n")

    # Add HBA entry for 127.0.0.2
    with pg2.hba_path.open() as f:
        old_hba = f.read()
    with pg2.hba_path.open(mode="w") as f:
        f.write("hostnossl  all  all  127.0.0.2/32  trust\n")
        f.write(old_hba)
    pg2.commit_hba()

    # Use same port as pg
    pg2.port_lock.release()
    pg2.port = pg.port

    run(f"pg_ctl -w --pgdata {pg2.pgdata} -o \"-p {pg.port}\" -l {pg2.log_path} start")

    pg2.sql("create database p0")
    pg2.sql("create user bouncer")
    pg2.sql("grant all on schema public to public", dbname="p0")

    yield pg2

    run(f"pg_ctl -w --pgdata {pg2.pgdata} -m fast stop", check=False)
    sudo("ip addr del 127.0.0.2/8 dev lo", check=False)


async def get_server_port(conn):
    """Get the Postgres server port this connection is using."""
    async with conn.cursor() as cur:
        await cur.execute("SELECT inet_server_port()")
        result = await cur.fetchone()
        return result[0]


async def get_server_addr(conn):
    """Get the Postgres server IP address this connection is using."""
    async with conn.cursor() as cur:
        await cur.execute("SELECT inet_server_addr()")
        result = await cur.fetchone()
        return str(result[0]) if result[0] else None


@pytest.fixture
async def bouncer_lb(pg, pg2, tmp_path):
    """PgBouncer configured for round-robin load balancing across two Postgres instances."""
    bouncer = Bouncer(pg, tmp_path / "bouncer_lb")

    with bouncer.ini_path.open("r") as f:
        ini_content = f.read()

    # Use 'localhost' instead of '127.0.0.1' to avoid conflicts with hostlist_* databases
    # which also use 127.0.0.1 (with the same port after substitution). The hash key
    # 'localhost:{port}' is different from '127.0.0.1:{port}'.
    db_entry = (
        f"lb_test = host=localhost,localhost port={pg.port},{pg2.port} dbname=p0 user=bouncer "
        f"pool_size=10 pool_mode=session load_balance_hosts=round-robin\n"
    )
    ini_content = ini_content.replace("[databases]\n", f"[databases]\n{db_entry}")

    with bouncer.ini_path.open("w") as f:
        f.write(ini_content)

    await bouncer.start()

    bouncer._pg_port = pg.port
    bouncer._pg2_port = pg2.port

    yield bouncer

    await bouncer.cleanup()


@pytest.fixture
async def bouncer_single_port(pg, tmp_path):
    """PgBouncer configured with a single host and single port."""
    bouncer = Bouncer(pg, tmp_path / "bouncer_single_port")

    with bouncer.ini_path.open("r") as f:
        ini_content = f.read()

    db_entry = (
        f"single_port_test = host=127.0.0.1 port={pg.port} dbname=p0 user=bouncer "
        f"pool_size=10 pool_mode=session\n"
    )
    ini_content = ini_content.replace("[databases]\n", f"[databases]\n{db_entry}")

    with bouncer.ini_path.open("w") as f:
        f.write(ini_content)

    await bouncer.start()

    yield bouncer

    await bouncer.cleanup()


@pytest.fixture
async def bouncer_multi_host_single_port(pg, pg2_same_port, tmp_path):
    """PgBouncer with two hosts (different IPs) but same port."""
    bouncer = Bouncer(pg, tmp_path / "bouncer_multi_single")

    with bouncer.ini_path.open("r") as f:
        ini_content = f.read()

    # Two different IPs, same port - tests that single port is replicated to all hosts
    # Use 'localhost' instead of '127.0.0.1' to avoid conflicts with hostlist_* databases
    db_entry = (
        f"multi_single_test = host=localhost,127.0.0.2 port={pg.port} dbname=p0 user=bouncer "
        f"pool_size=10 pool_mode=session load_balance_hosts=round-robin\n"
    )
    ini_content = ini_content.replace("[databases]\n", f"[databases]\n{db_entry}")

    with bouncer.ini_path.open("w") as f:
        f.write(ini_content)

    await bouncer.start()

    bouncer._pg_port = pg.port

    yield bouncer

    await bouncer.cleanup()


@pytest.fixture
async def bouncer_failover(pg, pg2, tmp_path):
    """PgBouncer configured for failover (disable) with two hosts/ports."""
    bouncer = Bouncer(pg, tmp_path / "bouncer_failover")

    with bouncer.ini_path.open("r") as f:
        ini_content = f.read()

    # Use 'localhost' instead of '127.0.0.1' to avoid conflicts with hostlist_* databases
    db_entry = (
        f"failover_test = host=localhost,localhost port={pg.port},{pg2.port} dbname=p0 user=bouncer "
        f"pool_size=10 pool_mode=session load_balance_hosts=disable\n"
    )
    ini_content = ini_content.replace("[databases]\n", f"[databases]\n{db_entry}")

    with bouncer.ini_path.open("w") as f:
        f.write(ini_content)

    await bouncer.start()

    bouncer._pg_port = pg.port
    bouncer._pg2_port = pg2.port

    yield bouncer

    await bouncer.cleanup()


async def test_load_unload(bouncer_lb):
    """Test that connections alternate between servers in round-robin fashion."""
    bouncer = bouncer_lb
    pg_port = bouncer._pg_port
    pg2_port = bouncer._pg2_port

    # First, make two simple connections to verify round-robin works
    conn1 = await bouncer.aconn(dbname="lb_test")
    port1 = await get_server_port(conn1)

    conn2 = await bouncer.aconn(dbname="lb_test")
    port2 = await get_server_port(conn2)

    await conn1.close()
    await conn2.close()

    # Verify connections went to different ports
    assert port1 != port2, f"Expected round-robin to different ports, but both went to {port1}"

    # Open 10 more connections and verify round-robin alternates between servers
    conns = []
    ports_seen = {pg_port: 0, pg2_port: 0}
    prev_port = None

    try:
        for i in range(10):
            conn = await bouncer.aconn(dbname="lb_test")
            conns.append(conn)
            server_port = await get_server_port(conn)
            ports_seen[server_port] = ports_seen.get(server_port, 0) + 1

            # Round-robin should alternate between ports
            if prev_port is not None:
                assert server_port != prev_port, \
                    f"Connection {i} went to same server as {i-1}: {server_port}"
            prev_port = server_port

        # Verify both servers got connections (should be 5 each with round-robin)
        assert ports_seen[pg_port] == 5, f"Expected 5 connections to {pg_port}, got {ports_seen[pg_port]}"
        assert ports_seen[pg2_port] == 5, f"Expected 5 connections to {pg2_port}, got {ports_seen[pg2_port]}"

    finally:
        for conn in conns:
            try:
                await conn.close()
            except Exception:
                pass  # Already closed


async def test_failover_uses_first_host(bouncer_failover):
    """Test that load_balance_hosts=disable always uses the first host."""
    bouncer = bouncer_failover
    pg_port = bouncer._pg_port

    conns = []
    try:
        # All connections should go to the first host
        for i in range(5):
            conn = await bouncer.aconn(dbname="failover_test")
            conns.append(conn)
            server_port = await get_server_port(conn)
            assert server_port == pg_port, \
                f"Connection {i} went to {server_port}, expected {pg_port} (first host)"
    finally:
        for conn in conns:
            try:
                await conn.close()
            except Exception:
                pass


async def test_single_port_for_single_host(bouncer_single_port):
    """Test that a single host with single port works correctly."""
    bouncer = bouncer_single_port

    conn = await bouncer.aconn(dbname="single_port_test")
    try:
        server_port = await get_server_port(conn)
        # Should connect successfully to the configured port
        assert server_port is not None
    finally:
        await conn.close()


async def test_multi_host_single_port(bouncer_multi_host_single_port):
    """Test that multiple hosts with single port works (port replicated to all hosts).

    This test requires USE_SUDO=1 to set up 127.0.0.2 as a loopback alias.
    Two Postgres instances run on localhost (::1 or 127.0.0.1) and 127.0.0.2, both on the same port.
    """
    bouncer = bouncer_multi_host_single_port

    conns = []
    # localhost may resolve to ::1 or 127.0.0.1, track both
    addrs_seen = {}
    prev_addr = None

    try:
        for i in range(10):
            conn = await bouncer.aconn(dbname="multi_single_test")
            conns.append(conn)
            server_addr = await get_server_addr(conn)
            addrs_seen[server_addr] = addrs_seen.get(server_addr, 0) + 1

            # Round-robin should alternate between addresses
            if prev_addr is not None:
                assert server_addr != prev_addr, \
                    f"Connection {i} went to same server as {i-1}: {server_addr}"
            prev_addr = server_addr

        # Verify we got exactly 2 different addresses with 5 connections each
        assert len(addrs_seen) == 2, f"Expected 2 different addresses, got {list(addrs_seen.keys())}"
        for addr, count in addrs_seen.items():
            assert count == 5, f"Expected 5 connections to {addr}, got {count}"

    finally:
        for conn in conns:
            try:
                await conn.close()
            except Exception:
                pass


async def test_connection_reuse_prefers_least_loaded(bouncer_lb):
    """Test that connection reuse prefers hosts with fewer active connections."""
    bouncer = bouncer_lb
    pg_port = bouncer._pg_port
    pg2_port = bouncer._pg2_port

    # Phase 1: Open 4 connections (2 to each server via round-robin)
    conns = []
    try:
        for i in range(4):
            conn = await bouncer.aconn(dbname="lb_test")
            conns.append(conn)

        # Verify distribution: 2 connections to each server
        ports = [await get_server_port(c) for c in conns]
        assert ports.count(pg_port) == 2, f"Expected 2 connections to {pg_port}"
        assert ports.count(pg2_port) == 2, f"Expected 2 connections to {pg2_port}"

        # Phase 2: Close connections to first server only
        # Find and close connections to pg_port
        for i, conn in enumerate(conns):
            if ports[i] == pg_port:
                await conn.close()
                conns[i] = None

        # Phase 3: Open new connections - they should prefer pg_port (less loaded)
        # The server now has: pg_port=0 active, pg2_port=2 active
        # New connections should go to pg_port first
        new_conns = []
        new_ports = []
        for i in range(4):
            conn = await bouncer.aconn(dbname="lb_test")
            new_conns.append(conn)
            port = await get_server_port(conn)
            new_ports.append(port)

        # With least-connections reuse, the first 2 new connections should go to pg_port
        # (bringing it to 2), then alternate
        assert new_ports[0] == pg_port, \
            f"First new connection should go to less loaded server {pg_port}, got {new_ports[0]}"
        assert new_ports[1] == pg_port, \
            f"Second new connection should go to less loaded server {pg_port}, got {new_ports[1]}"

        # After balancing, remaining connections should alternate
        # pg_port=2, pg2_port=2, so next connections alternate
        for conn in new_conns:
            await conn.close()

    finally:
        for conn in conns:
            if conn:
                try:
                    await conn.close()
                except Exception:
                    pass


async def test_port_count_mismatch_error(bouncer_lb):
    """Test that mismatched host/port counts cause a config error on reload."""
    bouncer = bouncer_lb

    # Read current config
    with bouncer.ini_path.open("r") as f:
        original_config = f.read()

    try:
        # Write config with mismatched port count (3 hosts, 2 ports)
        bad_config = original_config.replace(
            "[databases]\n",
            "[databases]\n"
            "bad_db = host=127.0.0.1,127.0.0.1,127.0.0.1 port=5432,5433 dbname=p0 user=bouncer\n"
        )
        with bouncer.ini_path.open("w") as f:
            f.write(bad_config)

        # Reload should fail due to port count mismatch
        with pytest.raises(psycopg.errors.ConfigFileError):
            bouncer.admin("RELOAD")

    finally:
        # Restore original config
        with bouncer.ini_path.open("w") as f:
            f.write(original_config)
        bouncer.admin("RELOAD")
