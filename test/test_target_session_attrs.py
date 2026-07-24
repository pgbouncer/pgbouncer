import asyncio
import os
import re
import socket
import struct
import subprocess
import time
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

from .utils import PG_MAJOR_VERSION, USE_UNIX_SOCKETS, Postgres, run

REPLICA_SOCKET_DIR = Path("/tmp/pgbouncer-test-replica")
requires_replica = pytest.mark.skipif(
    PG_MAJOR_VERSION < 14 or not USE_UNIX_SOCKETS,
    reason="target role tests require PostgreSQL 14+ and Unix sockets",
)


@pytest.fixture(scope="session")
def target_replica(pg, tmp_path_factory):
    pg.reset_hba()
    os.truncate(pg.pgdata / "postgresql.auto.conf", 0)
    if pg.restarted:
        pg.restart()
        pg.restarted = False
    else:
        pg.reload()

    replica = Postgres(tmp_path_factory.getbasetemp() / "pgdata_target_replica")
    replica.port_lock.release()
    replica.port = pg.port
    replica.host = str(REPLICA_SOCKET_DIR)

    REPLICA_SOCKET_DIR.mkdir(exist_ok=True)
    run(
        [
            "pg_basebackup",
            "--pgdata",
            str(replica.pgdata),
            "--write-recovery-conf",
            "--checkpoint=fast",
            "--no-sync",
            "--host",
            pg.host,
            "--port",
            str(pg.port),
            "--username",
            "postgres",
        ],
        env={**os.environ, "PGSSLMODE": "disable"},
        stdout=subprocess.DEVNULL,
    )
    with replica.conf_path.open("a") as conf:
        conf.write(f"port = {pg.port}\n")
        conf.write("listen_addresses = ''\n")
        conf.write(f"unix_socket_directories = '{REPLICA_SOCKET_DIR}'\n")
        conf.write("default_transaction_read_only = on\n")
    replica.start()

    try:
        yield replica
    finally:
        replica.stop()


@pytest.fixture(autouse=True)
def target_retry_settings(bouncer):
    bouncer.admin("SET server_login_retry=1")
    bouncer.admin("SET client_login_timeout=5")


def selected_role(bouncer, dbname):
    return bouncer.sql_value(
        "SELECT pg_is_in_recovery()", dbname=dbname, connect_timeout=10
    )


def startup_parameters(bouncer, dbname):
    startup = (
        struct.pack("!I", 196608)
        + b"user\0bouncer\0"
        + f"database\0{dbname}\0".encode()
        + b"\0"
    )

    def recv_exact(sock, size):
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                pytest.fail("server closed the connection during startup")
            data += chunk
        return data

    parameters = []
    with socket.create_connection((bouncer.host, bouncer.port), timeout=10) as sock:
        sock.sendall(struct.pack("!I", len(startup) + 4) + startup)
        while True:
            message_type = recv_exact(sock, 1)
            message_length = struct.unpack("!I", recv_exact(sock, 4))[0]
            message = recv_exact(sock, message_length - 4)
            if message_type == b"S":
                key, value, _ = message.split(b"\0")
                parameters.append((key.decode(), value.decode()))
            elif message_type == b"E":
                pytest.fail(f"startup failed: {message!r}")
            elif message_type == b"Z":
                return parameters


def test_target_session_attrs_admin_output(bouncer):
    databases = {
        row["name"]: row
        for row in bouncer.admin("SHOW DATABASES", row_factory=dict_row)
    }
    assert databases["tsa_version_any"]["target_session_attrs"] == "any"
    assert databases["tsa_version_primary"]["target_session_attrs"] == "primary"
    assert databases["tsa_default_any"]["target_session_attrs"] == "any"

    bouncer.test(dbname="tsa_version_any")
    bouncer.test(dbname="p0")
    if PG_MAJOR_VERSION >= 14:
        bouncer.test(dbname="tsa_version_primary")
    pools = {
        row["database"]: row
        for row in bouncer.admin("SHOW POOLS", row_factory=dict_row)
    }
    assert pools["tsa_version_any"]["target_session_attrs"] == "any"
    assert pools["p0"]["target_session_attrs"] == "any"
    if PG_MAJOR_VERSION >= 14:
        assert pools["tsa_version_primary"]["target_session_attrs"] == "primary"


@requires_replica
@pytest.mark.parametrize(
    "dbname,expected",
    [
        ("tsa_primary", False),
        ("tsa_standby", True),
        ("tsa_read_write", False),
        ("tsa_read_only", True),
        ("tsa_any", True),
    ],
)
def test_target_session_attrs_selects_matching_server(
    bouncer, target_replica, dbname, expected
):
    assert selected_role(bouncer, dbname) is expected


@requires_replica
async def test_target_session_attrs_default_any_uses_both_servers(
    bouncer, target_replica
):
    with bouncer.log_contains(r'parameter "in_hot_standby" cannot be changed', times=0):
        results = await asyncio.gather(
            bouncer.asql(
                "SELECT pg_is_in_recovery(), pg_sleep(0.5)",
                dbname="tsa_default_any",
            ),
            bouncer.asql(
                "SELECT pg_is_in_recovery(), pg_sleep(0.5)",
                dbname="tsa_default_any",
            ),
        )
    assert {rows[0][0] for rows in results} == {False, True}


@pytest.mark.skipif(
    PG_MAJOR_VERSION < 14,
    reason="default_transaction_read_only was not reported before PostgreSQL 14",
)
def test_target_session_attrs_read_only_primary(bouncer, pg):
    pg.sql("ALTER DATABASE p0 SET default_transaction_read_only=on")
    try:
        assert selected_role(bouncer, "tsa_read_only_primary") is False
        assert selected_role(bouncer, "tsa_primary_read_only") is False
        bouncer.admin("SET client_login_timeout=2")
        with pytest.raises(
            psycopg.OperationalError,
            match=r"client_login_timeout \(server down\)",
        ):
            bouncer.test(dbname="tsa_read_write_primary", connect_timeout=10)
    finally:
        pg.sql("ALTER DATABASE p0 RESET default_transaction_read_only")


@pytest.mark.skipif(
    PG_MAJOR_VERSION < 14,
    reason="default_transaction_read_only was not reported before PostgreSQL 14",
)
def test_target_session_attrs_observes_connect_query(bouncer):
    with bouncer.conn(dbname="tsa_connect_query", connect_timeout=10) as conn:
        assert conn.execute("SELECT pg_is_in_recovery()").fetchone() == (False,)
        assert conn.info.parameter_status("in_hot_standby") == "off"
        assert conn.info.parameter_status("default_transaction_read_only") == "on"


@requires_replica
def test_target_session_attrs_reports_accepted_server(bouncer, target_replica):
    with bouncer.conn(dbname="tsa_primary", connect_timeout=10) as conn:
        assert conn.execute("SELECT pg_is_in_recovery()").fetchone() == (False,)
        assert conn.info.parameter_status("in_hot_standby") == "off"
        assert conn.info.parameter_status("default_transaction_read_only") == "off"


@requires_replica
def test_target_session_attrs_replication_retries_matching_server(
    bouncer, target_replica
):
    with (
        bouncer.log_contains("server does not satisfy target_session_attrs"),
        bouncer.conn(
            dbname="tsa_replication_read_write",
            user="postgres",
            replication="database",
            connect_timeout=10,
        ) as conn,
    ):
        assert conn.execute("SELECT pg_is_in_recovery()").fetchone() == (False,)
        assert conn.info.parameter_status("default_transaction_read_only") == "off"


@requires_replica
def test_rejected_server_parameters_are_not_cached(bouncer, target_replica):
    parameters = startup_parameters(bouncer, "tsa_primary")
    names = [name for name, _ in parameters]

    assert len(names) == len(set(names))
    assert dict(parameters)["in_hot_standby"] == "off"
    assert dict(parameters)["default_transaction_read_only"] == "off"


def terminate_idle_server(bouncer, pg, dbname):
    pid = bouncer.sql_value("SELECT pg_backend_pid()", dbname=dbname)
    assert pg.sql_value("SELECT pg_terminate_backend(%s)", (pid,)) is True

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        servers = bouncer.admin("SHOW SERVERS", row_factory=dict_row)
        if not any(server["database"] == dbname for server in servers):
            return
        time.sleep(0.05)
    pytest.fail(f"server for {dbname} was not removed")


@requires_replica
async def test_target_mismatch_does_not_fast_fail_waiting_client(
    bouncer, target_replica, pg
):
    bouncer.admin("SET server_login_retry=2")
    bouncer.admin("SET client_login_timeout=8")
    terminate_idle_server(bouncer, pg, "tsa_retry_primary")
    log_offset = bouncer.log_path.stat().st_size

    first = bouncer.asql(
        "SELECT pg_is_in_recovery()", dbname="tsa_retry_primary", connect_timeout=10
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with bouncer.log_path.open() as log:
            log.seek(log_offset)
            if "server does not satisfy target_session_attrs" in log.read():
                break
        await asyncio.sleep(0.05)
    else:
        pytest.fail("target mismatch was not logged")

    with bouncer.log_contains(r"server login has been failing", times=0):
        second = bouncer.asql(
            "SELECT pg_is_in_recovery()",
            dbname="tsa_retry_primary",
            connect_timeout=10,
        )
        results = await asyncio.gather(first, second)
    assert all(rows == [(False,)] for rows in results)


@requires_replica
async def test_target_mismatch_preserves_real_connection_failure(
    bouncer, target_replica, pg
):
    bouncer.admin("SET server_login_retry=1")
    bouncer.admin("SET client_login_timeout=8")
    terminate_idle_server(bouncer, pg, "tsa_mixed_failure")
    log_offset = bouncer.log_path.stat().st_size

    first = bouncer.asql(
        "SELECT pg_is_in_recovery()", dbname="tsa_mixed_failure", connect_timeout=10
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with bouncer.log_path.open() as log:
            log.seek(log_offset)
            content = log.read()
        if (
            "connect failed" in content
            and "server does not satisfy target_session_attrs" in content
        ):
            break
        await asyncio.sleep(0.05)
    else:
        pytest.fail("login failure followed by target mismatch was not logged")

    with pytest.raises(
        psycopg.OperationalError,
        match=r"server login has been failing, cached error: connect failed",
    ):
        await bouncer.asql(
            "SELECT pg_is_in_recovery()",
            dbname="tsa_mixed_failure",
            connect_timeout=10,
        )
    assert await first == [(False,)]


@requires_replica
def test_all_target_candidates_mismatch_times_out(bouncer, target_replica):
    bouncer.admin("SET client_login_timeout=3")
    with pytest.raises(
        psycopg.OperationalError, match=r"client_login_timeout \(server down\)"
    ):
        bouncer.test(dbname="tsa_all_mismatch", connect_timeout=10)


def test_target_session_attrs_version_boundary(bouncer):
    bouncer.test(dbname="tsa_version_any")
    if PG_MAJOR_VERSION >= 14:
        bouncer.test(dbname="tsa_version_primary")
    else:
        bouncer.admin("SET client_login_timeout=3")
        with pytest.raises(
            psycopg.OperationalError,
            match=r"client_login_timeout \(server down\)",
        ):
            bouncer.test(dbname="tsa_version_primary", connect_timeout=10)


@requires_replica
def test_target_session_attrs_reload_replaces_server(bouncer, target_replica):
    first_pid, first_in_recovery = bouncer.sql(
        "SELECT pg_backend_pid(), pg_is_in_recovery()", dbname="tsa_reload"
    )[0]
    assert first_in_recovery is True

    original = bouncer.ini_path.read_text()
    updated, replacements = re.subn(
        r"^(tsa_reload.*target_session_attrs=)any$",
        r"\1primary",
        original,
        flags=re.MULTILINE,
    )
    assert replacements == 1
    bouncer.ini_path.write_text(updated)
    bouncer.admin("RELOAD")
    bouncer.admin("SET server_login_retry=1")
    bouncer.admin("SET client_login_timeout=5")

    database = next(
        row
        for row in bouncer.admin("SHOW DATABASES", row_factory=dict_row)
        if row["name"] == "tsa_reload"
    )
    assert database["target_session_attrs"] == "primary"

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        servers = bouncer.admin("SHOW SERVERS", row_factory=dict_row)
        if not any(server["remote_pid"] == first_pid for server in servers):
            break
        time.sleep(0.05)
    else:
        pytest.fail("server from the old database configuration was not removed")

    second_pid, second_in_recovery = bouncer.sql(
        "SELECT pg_backend_pid(), pg_is_in_recovery()",
        dbname="tsa_reload",
        connect_timeout=10,
    )[0]
    assert second_in_recovery is False
    assert second_pid != first_pid


@requires_replica
async def test_target_session_attrs_takeover_reconnects_unknown_server(
    bouncer, target_replica
):
    first_pid, first_in_recovery = bouncer.sql(
        "SELECT pg_backend_pid(), pg_is_in_recovery()", dbname="tsa_takeover"
    )[0]
    assert first_in_recovery is True

    original = bouncer.ini_path.read_text()
    updated, replacements = re.subn(
        r"^(tsa_takeover.*target_session_attrs=)any$",
        r"\1primary",
        original,
        flags=re.MULTILINE,
    )
    assert replacements == 1
    bouncer.ini_path.write_text(updated)
    await bouncer.reboot()
    bouncer.admin("SET server_login_retry=1")
    bouncer.admin("SET client_login_timeout=5")

    second_pid, second_in_recovery = bouncer.sql(
        "SELECT pg_backend_pid(), pg_is_in_recovery()",
        dbname="tsa_takeover",
        connect_timeout=10,
    )[0]
    assert second_in_recovery is False
    assert second_pid != first_pid


def test_target_session_attrs_rejects_prefer_standby(bouncer):
    original = bouncer.ini_path.read_text()
    invalid, replacements = re.subn(
        r"target_session_attrs=primary$",
        "target_session_attrs=prefer-standby",
        original,
        count=1,
        flags=re.MULTILINE,
    )
    assert replacements == 1
    bouncer.ini_path.write_text(invalid)
    try:
        with pytest.raises(psycopg.errors.ConfigFileError):
            bouncer.admin("RELOAD")
    finally:
        bouncer.ini_path.write_text(original)
        bouncer.admin("RELOAD")
