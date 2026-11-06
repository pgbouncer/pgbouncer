import asyncio
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import psycopg
import pytest

from .utils import (
    DIRECT_TLS_SUPPORT,
    MACOS,
    PG_MAJOR_VERSION,
    PG_SUPPORTS_SCRAM,
    TEST_DIR,
    TLS_SUPPORT,
    USE_UNIX_SOCKETS,
    WINDOWS,
    Bouncer,
    TlsStubServer,
    wait_until,
)

if not TLS_SUPPORT:
    pytest.skip(allow_module_level=True)

# XXX: These test use psql to connect using sslmode=verify-full instead of
# using psycopg. The reason for this is that psycopg has a bug on Apple
# silicon when enabling SSL: https://github.com/psycopg/psycopg/discussions/270


# replace regular bouncer fixture with one that uses the special SSL config
@pytest.fixture
async def bouncer_tls(pg, tmp_path):
    bouncer_tls = Bouncer(
        pg, tmp_path / "bouncer", base_ini_path=TEST_DIR / "ssl" / "test.ini"
    )

    await bouncer_tls.start()

    yield bouncer_tls

    await bouncer_tls.cleanup()


def test_server_ssl(pg, bouncer_tls, cert_dir):
    bouncer_tls.admin("set server_tls_sslmode = require")
    pg.ssl_access("all", "trust")
    pg.configure("ssl=on")
    root = cert_dir / "TestCA1" / "ca.crt"
    pg.configure(f"ssl_ca_file='{root}'")
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
    bouncer_tls.test()


def test_server_ssl_set_disable(pg, bouncer_tls, cert_dir):
    bouncer_tls.admin("set server_tls_sslmode = require")
    pg.ssl_access("all", "trust")
    pg.configure("ssl=on")
    root = cert_dir / "TestCA1" / "ca.crt"
    pg.configure(f"ssl_ca_file='{root}'")
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()

    bouncer_tls.test()

    pg.reset_hba()
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
        bouncer_tls.test()  # connection is still cached

    bouncer_tls.admin("reconnect")
    with pytest.raises(
        psycopg.OperationalError,
        match="no pg_hba.conf entry for .*, (SSL encryption|SSL on)",
    ):
        bouncer_tls.test()
    # XXX: It would be nice if this reset server_login_retry, but it currently
    # doesn't. So we have server_login_retry=1 in the ini file.
    bouncer_tls.admin("set server_tls_sslmode = disable")
    bouncer_tls.test()


def test_server_ssl_set_enable(pg, bouncer_tls, cert_dir):
    bouncer_tls.admin("set server_tls_sslmode = disable")
    pg.configure("ssl=on")
    root = cert_dir / "TestCA1" / "ca.crt"
    pg.configure(f"ssl_ca_file='{root}'")
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()

    bouncer_tls.test()

    pg.nossl_access("all", "reject")
    pg.ssl_access("all", "trust")
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
        bouncer_tls.test()  # connection is still cached

    bouncer_tls.admin("reconnect")
    with pytest.raises(
        psycopg.OperationalError,
        match="pg_hba.conf rejects connection for .*, (no encryption|SSL off)",
    ):
        bouncer_tls.test()

    # XXX: It would be nice if this reset server_login_retry, but it currently
    # doesn't. So we have server_login_retry=1 in the ini file.
    bouncer_tls.admin("set server_tls_sslmode = require")
    bouncer_tls.test()


def test_server_ssl_verify(pg, bouncer_tls, cert_dir):
    bouncer_tls.admin("set server_tls_sslmode = 'verify-full'")
    root = cert_dir / "TestCA1" / "ca.crt"
    wrong_root = cert_dir / "TestCA2" / "ca.crt"
    bouncer_tls.admin(f"set server_tls_ca_file = '{wrong_root}'")
    pg.ssl_access("all", "trust")
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
    with (
        bouncer_tls.log_contains(r"certificate verify failed"),
        pytest.raises(
            psycopg.OperationalError,
            match="connection timeout expired",
        ),
    ):
        bouncer_tls.test(connect_timeout=4)
    bouncer_tls.admin(f"set server_tls_ca_file = '{root}'")
    bouncer_tls.test()

    bouncer_tls.psql_test(dbname="hostlistsslverify")


def test_server_ssl_auth(pg, bouncer_tls, cert_dir):
    bouncer_tls.admin("set server_tls_sslmode = 'verify-full'")
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "02-bouncer.key"
    cert = cert_dir / "TestCA1" / "sites" / "02-bouncer.crt"
    bouncer_tls.admin(f"set server_tls_ca_file = '{root}'")
    bouncer_tls.admin(f"set server_tls_key_file = '{key}'")
    bouncer_tls.admin(f"set server_tls_cert_file = '{cert}'")
    pg.ssl_access("all", "cert")
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
    bouncer_tls.test()


def test_client_ssl(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.admin(f"set client_tls_key_file = '{key}'")
    bouncer_tls.admin(f"set client_tls_cert_file = '{cert}'")
    bouncer_tls.admin(f"set client_tls_ca_file = '{root}'")
    bouncer_tls.admin(f"set client_tls_sslmode = require")
    bouncer_tls.psql_test(host="localhost", sslmode="require")


def test_client_ssl_set_enable_disable(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.admin(f"set client_tls_key_file = '{key}'")
    bouncer_tls.admin(f"set client_tls_cert_file = '{cert}'")
    bouncer_tls.admin(f"set client_tls_ca_file = '{root}'")
    bouncer_tls.admin(f"set client_tls_sslmode = require")
    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    bouncer_tls.admin(f"set client_tls_sslmode = disable")
    bouncer_tls.test(sslmode="disable")

    bouncer_tls.admin(f"set client_tls_sslmode = require")
    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)


def test_client_ssl_set_change_ca(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.admin(f"set client_tls_key_file = '{key}'")
    bouncer_tls.admin(f"set client_tls_cert_file = '{cert}'")
    bouncer_tls.admin(f"set client_tls_ca_file = '{root}'")
    bouncer_tls.admin(f"set client_tls_sslmode = require")
    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    new_root = cert_dir / "TestCA2" / "ca.crt"
    new_key = cert_dir / "TestCA2" / "sites" / "01-localhost.key"
    new_cert = cert_dir / "TestCA2" / "sites" / "01-localhost.crt"
    bouncer_tls.admin(f"set client_tls_key_file = '{new_key}'")
    bouncer_tls.admin(f"set client_tls_cert_file = '{new_cert}'")
    bouncer_tls.admin(f"set client_tls_ca_file = '{new_root}'")

    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)
    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=new_root)


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_client_ssl_sighup_enable_disable(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = require")
    bouncer_tls.sighup()

    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    bouncer_tls.write_ini(f"client_tls_sslmode = disable")
    bouncer_tls.sighup()
    bouncer_tls.test(sslmode="disable")


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_client_ssl_sighup_change_ca(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = require")
    bouncer_tls.sighup()

    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    new_root = cert_dir / "TestCA2" / "ca.crt"
    new_key = cert_dir / "TestCA2" / "sites" / "01-localhost.key"
    new_cert = cert_dir / "TestCA2" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {new_key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {new_cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {new_root}")
    bouncer_tls.sighup()

    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)
    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=new_root)


def test_client_ssl_reload_enable_disable(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = require")
    bouncer_tls.admin("reload")

    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    bouncer_tls.write_ini(f"client_tls_sslmode = disable")
    bouncer_tls.admin("reload")
    bouncer_tls.test(sslmode="disable")


def test_client_ssl_reload_change_ca(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = require")
    bouncer_tls.admin("reload")

    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    new_root = cert_dir / "TestCA2" / "ca.crt"
    new_key = cert_dir / "TestCA2" / "sites" / "01-localhost.key"
    new_cert = cert_dir / "TestCA2" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {new_key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {new_cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {new_root}")
    bouncer_tls.admin("reload")

    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)
    bouncer_tls.psql_test(host="localhost", sslmode="verify-full", sslrootcert=new_root)


def test_client_ssl_auth(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = verify-full")
    bouncer_tls.write_ini(f"auth_type = cert")
    bouncer_tls.admin("reload")

    client_key = cert_dir / "TestCA1" / "sites" / "02-bouncer.key"
    client_cert = cert_dir / "TestCA1" / "sites" / "02-bouncer.crt"
    bouncer_tls.psql_test(
        host="localhost",
        sslmode="verify-full",
        user="bouncer",
        sslrootcert=root,
        sslkey=client_key,
        sslcert=client_cert,
    )


@pytest.mark.skipif("not PG_SUPPORTS_SCRAM")
def test_client_ssl_scram(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = require")
    bouncer_tls.write_ini(f"auth_type = scram-sha-256")
    bouncer_tls.admin("reload")

    bouncer_tls.psql_test(
        host="localhost",
        user="bouncer",
        password="zzzz",
        sslmode="verify-full",
        sslrootcert=root,
    )


def test_ssl_replication(pg, bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"

    bouncer_tls.write_ini(f"server_tls_sslmode = verify-full")
    bouncer_tls.write_ini(f"server_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = require")
    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.admin("reload")
    pg.ssl_access("all", "trust")
    pg.ssl_access("replication", "trust", user="postgres")
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")

    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()

    # Logical rep
    connect_args = {
        "host": "localhost",
        "dbname": "p7a",
        "replication": "database",
        "user": "postgres",
        "application_name": "abc",
        "sslmode": "verify-full",
        "sslrootcert": root,
    }
    bouncer_tls.psql("IDENTIFY_SYSTEM", **connect_args)
    # physical rep
    connect_args["replication"] = "true"
    bouncer_tls.psql("IDENTIFY_SYSTEM", **connect_args)


def test_servers_no_disconnect_on_reload_with_no_tls_change(bouncer_tls, pg, cert_dir):
    bouncer_tls.default_db = "pTxnPool"

    with bouncer_tls.cur() as cur:
        assert pg.connection_count(dbname="p0") == 1

        with bouncer_tls.log_contains(
            r"pTxnPool.*database configuration changed|pTxnPool.*obsolete connection", 0
        ):
            # change nothing and RELOAD
            bouncer_tls.admin("RELOAD")
            # keep cursor open for > full_maint_period
            # full_maint_period = 3x/s https://github.com/pgbouncer/pgbouncer/blob/master/src/janitor.c#L28
            time.sleep(0.5)
            assert pg.connection_count(dbname="p0") == 1
            cur.execute("SELECT 1")


def test_servers_disconnect_when_changing_tls_config(bouncer_tls, pg, cert_dir):
    bouncer_tls.default_db = "pTxnPool"
    bouncer_tls.write_ini(f"server_tls_protocols = tlsv1.0")
    bouncer_tls.admin("RELOAD")

    with bouncer_tls.cur() as cur:
        assert pg.connection_count(dbname="p0") == 1
        bouncer_tls.write_ini(f"server_tls_protocols = secure")

        with bouncer_tls.log_contains(
            r"pTxnPool.*database configuration changed|pTxnPool.*obsolete connection", 1
        ):
            bouncer_tls.admin("RELOAD")
            for _ in wait_until("Did not close connection"):
                if pg.connection_count(dbname="p0") == 0:
                    break
            cur.execute("SELECT 1")


def test_servers_disconnect_when_enabling_ssl(bouncer_tls, pg, cert_dir):
    bouncer_tls.default_db = "pTxnPool"
    bouncer_tls.write_ini(f"server_tls_sslmode = disable")
    bouncer_tls.admin("RELOAD")

    with bouncer_tls.cur() as cur:
        assert pg.connection_count(dbname="p0") == 1
        bouncer_tls.write_ini(f"server_tls_sslmode = allow")

        with bouncer_tls.log_contains(
            r"pTxnPool.*database configuration changed|pTxnPool.*obsolete connection"
        ):
            bouncer_tls.admin("RELOAD")
            cur.execute("SELECT 1")


def test_servers_disconnect_when_changing_sslmode(bouncer_tls, pg, cert_dir):
    bouncer_tls.default_db = "pTxnPool"

    with bouncer_tls.cur() as cur:
        assert pg.connection_count(dbname="p0") == 1
        bouncer_tls.write_ini(f"server_tls_sslmode = allow")

        with bouncer_tls.log_contains(
            r"pTxnPool.*database configuration changed|pTxnPool.*obsolete connection"
        ):
            bouncer_tls.admin("RELOAD")
            cur.execute("SELECT 1")


def test_client_ssl_set_ciphers_for_tls_v1_3(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = require")

    bouncer_tls.write_ini("client_tls_protocols=tlsv1.3")
    bouncer_tls.write_ini("client_tls13_ciphers=TLS_CHACHA20_POLY1305_SHA256")

    bouncer_tls.admin("reload")

    with bouncer_tls.log_contains(r"tls=TLSv1.3/TLS_CHACHA20_POLY1305_SHA256"):
        bouncer_tls.psql_test(host="localhost", sslmode="require")

    bouncer_tls.admin("set client_tls13_ciphers='TLS_AES_256_GCM_SHA384'")

    with bouncer_tls.log_contains(r"tls=TLSv1.3/TLS_AES_256_GCM_SHA384"):
        bouncer_tls.psql_test(host="localhost", sslmode="require")

    with bouncer_tls.log_contains(r"failed to set the TLSv1.3 cipher suites"):
        bouncer_tls.admin(f"set client_tls13_ciphers = 'unknown'")


@pytest.mark.skipif(
    "not DIRECT_TLS_SUPPORT", reason="Direct TLS is introduced in PG 17"
)
def test_client_direct_ssl(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.admin(f"set client_tls_key_file = '{key}'")
    bouncer.admin(f"set client_tls_cert_file = '{cert}'")
    bouncer.admin(f"set client_tls_ca_file = '{root}'")
    bouncer.admin("set client_tls_sslmode = require")
    bouncer.psql_test(host="localhost", sslmode="require", sslnegotiation="direct")


def test_system_error_propagation(bouncer_tls, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"

    nonexistent_cert = cert_dir / "dummy.crt"
    if nonexistent_cert.exists():
        nonexistent_cert.unlink()

    bouncer_tls.write_ini(f"client_tls_key_file = {key}")
    bouncer_tls.write_ini(f"client_tls_cert_file = {nonexistent_cert}")
    bouncer_tls.write_ini(f"client_tls_ca_file = {root}")
    bouncer_tls.write_ini(f"client_tls_sslmode = require")

    with bouncer_tls.log_contains(
        r"ERROR TLS setup failed:[^\n]*No such file or directory"
    ):
        try:
            bouncer_tls.admin("RELOAD")
        # System error will cause an exception during RELOAD command. Ignore it
        # since it is expected.
        except psycopg.errors.ConfigFileError as e:
            assert "RELOAD failed" in str(e)


# ---------------------------------------------------------------------------
# server_tls_direct tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    "not DIRECT_TLS_SUPPORT", reason="Direct TLS requires PG 17+ with TLS support"
)
def test_server_tls_direct_basic(pg, bouncer_tls, cert_dir):
    """Bouncer connects to PG using direct TLS (no SSLRequest round-trip)."""
    root = cert_dir / "TestCA1" / "ca.crt"

    # Enable SSL on PG, allow only SSL connections (reject plain TCP)
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")
    pg.ssl_access("all", "trust")
    pg.nossl_access("all", "reject")
    pg.reload()

    bouncer_tls.write_ini(f"server_tls_sslmode = require")
    bouncer_tls.write_ini(f"server_tls_ca_file = {root}")
    bouncer_tls.write_ini("server_tls_direct = 1")
    bouncer_tls.admin("reload")

    with bouncer_tls.log_contains(r"SSL established"):
        bouncer_tls.test()


@pytest.mark.skipif(
    "not DIRECT_TLS_SUPPORT", reason="Direct TLS requires PG 17+ with TLS support"
)
def test_server_tls_direct_verify_full(pg, bouncer_tls, cert_dir):
    """Direct TLS works with verify-full — cert validation is orthogonal to transport."""
    root = cert_dir / "TestCA1" / "ca.crt"

    # Enable SSL on PG, allow only SSL connections (reject plain TCP)
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")
    pg.ssl_access("all", "trust")
    pg.nossl_access("all", "reject")
    pg.reload()

    bouncer_tls.write_ini(f"server_tls_sslmode = verify-full")
    bouncer_tls.write_ini(f"server_tls_ca_file = {root}")
    bouncer_tls.write_ini("server_tls_direct = 1")
    bouncer_tls.admin("reload")

    with bouncer_tls.log_contains(r"SSL established"):
        bouncer_tls.test()


@pytest.mark.skipif(
    "not DIRECT_TLS_SUPPORT", reason="Direct TLS requires PG 17+ with TLS support"
)
def test_server_tls_direct_plain_server_fails(pg, bouncer_tls, cert_dir):
    """Direct TLS against a plain-TCP server fails — no fallback to unencrypted."""
    bouncer_tls.write_ini("server_tls_sslmode = require")
    bouncer_tls.write_ini("server_tls_direct = 1")
    bouncer_tls.admin("reload")

    # PostgreSQL with ssl=off speaks plain TCP; the direct TLS handshake will fail
    pg.configure("ssl=off")
    pg.restart()

    with pytest.raises(psycopg.OperationalError):
        bouncer_tls.test(connect_timeout=4)


def test_server_tls_direct_disabled_sslmode_rejected(bouncer_tls):
    """server_tls_direct=1 combined with sslmode=disable must be rejected at reload."""
    bouncer_tls.write_ini("server_tls_sslmode = disable")
    bouncer_tls.write_ini("server_tls_direct = 1")

    with bouncer_tls.log_contains(
        r"server_tls_direct requires server_tls_sslmode to not be 'disable'"
    ):
        try:
            bouncer_tls.admin("RELOAD")
        except psycopg.errors.ConfigFileError:
            pass


@pytest.mark.skipif(
    "not DIRECT_TLS_SUPPORT", reason="Direct TLS requires PG 17+ with TLS support"
)
def test_server_tls_direct_reconnect_on_flag_change(bouncer_tls, pg, cert_dir):
    """Changing server_tls_direct triggers pool reconnect (marks connections dirty)."""
    root = cert_dir / "TestCA1" / "ca.crt"
    bouncer_tls.default_db = "pTxnPool"

    # Start with STARTTLS (server_tls_direct=0), SSL required
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")
    pg.ssl_access("all", "trust")
    pg.reload()

    bouncer_tls.write_ini(f"server_tls_sslmode = require")
    bouncer_tls.write_ini(f"server_tls_ca_file = {root}")
    bouncer_tls.write_ini("server_tls_direct = 0")
    bouncer_tls.admin("reload")

    with bouncer_tls.cur() as cur:
        assert pg.connection_count(dbname="p0") == 1
        # Switch to direct TLS — should mark the STARTTLS connection as dirty
        bouncer_tls.write_ini("server_tls_direct = 1")

        with bouncer_tls.log_contains(
            r"pTxnPool.*database configuration changed|pTxnPool.*obsolete connection"
        ):
            bouncer_tls.admin("RELOAD")
            cur.execute("SELECT 1")


# ---------------------------------------------------------------------------
# Stub-server based direct-TLS tests
#
# These use TlsStubServer instead of a real Postgres backend, so they only
# require TLS_SUPPORT (not PG 17+), and they can observe things a real backend
# hides: whether the first byte was TLS, the SNI, the ALPN, and which
# PostgreSQL message arrived first.
# ---------------------------------------------------------------------------

PKT_STARTUP = TlsStubServer.PKT_STARTUP
PKT_CANCEL = TlsStubServer.PKT_CANCEL

requires_tls = pytest.mark.skipif("not TLS_SUPPORT", reason="Requires TLS support")


@asynccontextmanager
async def stub_bouncer(
    pg, tmp_path, cert_dir, stub, *, name, sslmode="require", direct=True, host=None
):
    """Start a bouncer whose database p0 points at the given TlsStubServer."""
    root = cert_dir / "TestCA1" / "ca.crt"
    bouncer = Bouncer(pg, tmp_path / name, base_ini_path=TEST_DIR / "ssl" / "test.ini")
    # Settings must be written before [databases], otherwise they would land
    # in the databases section.
    bouncer.write_ini(f"server_tls_sslmode = {sslmode}")
    bouncer.write_ini(f"server_tls_ca_file = {root}")
    bouncer.write_ini(f"server_tls_direct = {int(direct)}")
    bouncer.write_ini(
        f"[databases]\np0 = host={host or stub.host} port={stub.port} "
        "dbname=p0 user=bouncer"
    )
    await bouncer.start()
    try:
        yield bouncer
    finally:
        await bouncer.cleanup()


def wait_for_records(stub, count, timeout=5):
    for _ in wait_until(f"stub did not see {count} connections", timeout=timeout):
        records = stub.snapshot()
        if len(records) >= count:
            return records


def start_blocked_query(bouncer, pool, stub):
    """Run a query through the bouncer that the stub never answers, and wait
    until it reached the stub. Returns the stub record of the login connection."""
    conn = bouncer.conn(dbname="p0")
    pool.submit(conn.execute, "select pg_sleep(60)")
    login = stub.wait_for(lambda r: "Q" in r["tags"])
    return conn, login


@requires_tls
async def test_server_tls_direct_rejects_missing_alpn(pg, tmp_path, cert_dir):
    """A1: a TLS server that selects no ALPN protocol is rejected before any
    StartupMessage is sent."""
    with TlsStubServer(cert_dir, alpn=None) as stub:
        async with stub_bouncer(pg, tmp_path, cert_dir, stub, name="a1") as bouncer:
            with (
                bouncer.log_contains(r"without ALPN protocol negotiation"),
                pytest.raises(psycopg.OperationalError),
            ):
                bouncer.test(connect_timeout=2)
            records = stub.snapshot()
            assert records
            for r in records:
                assert r["first_byte_is_tls"] is True
                assert r["alpn"] is None
                assert r["first_message_type"] is None


@requires_tls
async def test_server_tls_direct_accepts_alpn_postgresql(pg, tmp_path, cert_dir):
    """A2: ALPN 'postgresql' is offered by the bouncer and accepted."""
    with TlsStubServer(cert_dir, alpn="postgresql") as stub:
        async with stub_bouncer(pg, tmp_path, cert_dir, stub, name="a2") as bouncer:
            bouncer.test()
            rec = stub.wait_for(lambda r: r["first_message_type"] == PKT_STARTUP)
            assert rec["first_byte_is_tls"] is True
            assert rec["alpn"] == "postgresql"


@requires_tls
async def test_server_tls_starttls_does_not_require_alpn(pg, tmp_path, cert_dir):
    """A3: on the SSLRequest (STARTTLS) path a server without ALPN is fine."""
    with TlsStubServer(cert_dir, alpn=None, starttls=True) as stub:
        async with stub_bouncer(
            pg, tmp_path, cert_dir, stub, name="a3", direct=False
        ) as bouncer:
            bouncer.test()
            rec = stub.wait_for(lambda r: r["first_message_type"] == PKT_STARTUP)
            assert rec["alpn"] is None


@requires_tls
@pytest.mark.parametrize("sslmode", ["require", "verify-ca", "verify-full"])
async def test_server_tls_direct_sends_sni(pg, tmp_path, cert_dir, sslmode):
    """S1: SNI is sent in the ClientHello for every sslmode."""
    with TlsStubServer(cert_dir, alpn="postgresql") as stub:
        async with stub_bouncer(
            pg,
            tmp_path,
            cert_dir,
            stub,
            name=f"s1_{sslmode}",
            sslmode=sslmode,
            host="localhost",
        ) as bouncer:
            bouncer.test()
            rec = stub.wait_for(lambda r: r["first_message_type"] == PKT_STARTUP)
            assert rec["sni"] == "localhost"


@requires_tls
async def test_server_tls_direct_cancel_uses_tls(pg, tmp_path, cert_dir):
    """C1: the cancel connection uses direct TLS and carries a CancelRequest."""
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        with TlsStubServer(cert_dir, alpn="postgresql") as stub:
            async with stub_bouncer(pg, tmp_path, cert_dir, stub, name="c1") as b:
                conn, login = start_blocked_query(b, pool, stub)
                assert login["first_byte_is_tls"] is True
                pool.submit(conn.cancel_safe, timeout=30)

                records = wait_for_records(stub, 2)
                cancel = records[1]
                assert cancel["first_byte_is_tls"] is True, (
                    "cancel connection was sent as plaintext"
                )
                rec = stub.wait_for(lambda r: r["first_message_type"] == PKT_CANCEL)
                assert rec["alpn"] == "postgresql"
                assert rec["first_byte_is_tls"] is True
    finally:
        pool.shutdown(wait=True)


@requires_tls
async def test_server_tls_direct_cancel_requires_alpn(pg, tmp_path, cert_dir):
    """C2: if the server stops selecting ALPN, the CancelRequest is never sent."""
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        with TlsStubServer(cert_dir, alpn="postgresql") as stub:
            async with stub_bouncer(pg, tmp_path, cert_dir, stub, name="c2") as b:
                conn, _login = start_blocked_query(b, pool, stub)
                stub.alpn = None
                pool.submit(conn.cancel_safe, timeout=30)

                wait_for_records(stub, 2)
                # Give the bouncer time to (wrongly) send the CancelRequest.
                await asyncio.sleep(1)
                cancel_conns = stub.snapshot()[1:]
                assert cancel_conns
                for r in cancel_conns:
                    assert r["first_byte_is_tls"] is True
                    assert r["alpn"] is None
                    assert r["first_message_type"] is None, "request sent without ALPN"
    finally:
        pool.shutdown(wait=True)


@requires_tls
async def test_server_tls_direct_cancel_client_gives_up(pg, tmp_path, cert_dir):
    """C3: the cancel client goes away while the cancel connection is still in
    its TLS handshake. The bouncer must survive, no CancelRequest may be sent
    and the server connection must end up as a normal, usable login."""
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        with TlsStubServer(cert_dir, alpn="postgresql") as stub:
            async with stub_bouncer(pg, tmp_path, cert_dir, stub, name="c3") as b:
                conn, _login = start_blocked_query(b, pool, stub)
                stub.handshake_delay = 2
                pool.submit(conn.cancel_safe, timeout=30)
                wait_for_records(stub, 2)

                cancel_ids = []
                for _ in wait_until("cancel client not visible"):
                    cancel_ids = [
                        row[-1] for row in b.admin("SHOW CLIENTS") if "cancel" in row[4]
                    ]
                    if cancel_ids:
                        break
                for cid in cancel_ids:
                    b.admin(f"KILL_CLIENT {cid}")

                # The delayed connection finishes its handshake and, since no
                # cancel is waiting anymore, performs a normal login.
                for _ in wait_until("delayed connection did not log in", timeout=10):
                    records = stub.snapshot()
                    if records[1]["first_message_type"] is not None:
                        break
                assert records[1]["first_message_type"] == PKT_STARTUP
                assert not any(
                    r["first_message_type"] == PKT_CANCEL for r in stub.snapshot()
                )
                for _ in wait_until("cancel client still present"):
                    if not any("cancel" in row[4] for row in b.admin("SHOW CLIENTS")):
                        break
                b.admin("SHOW VERSION")
    finally:
        pool.shutdown(wait=True)


@requires_tls
@pytest.mark.skipif("not USE_UNIX_SOCKETS", reason="Requires unix sockets")
async def test_server_tls_direct_unix_socket_unchanged(pg, tmp_path, cert_dir):
    """U1: unix socket servers are not affected by server_tls_direct."""
    bouncer = Bouncer(pg, tmp_path / "u1", base_ini_path=TEST_DIR / "ssl" / "test.ini")
    bouncer.write_ini("server_tls_sslmode = prefer")
    bouncer.write_ini("server_tls_direct = 1")
    bouncer.write_ini(
        f"[databases]\np0 = host=/tmp port={pg.port} dbname=p0 user=bouncer"
    )
    await bouncer.start()
    try:
        bouncer.test()
    finally:
        await bouncer.cleanup()
