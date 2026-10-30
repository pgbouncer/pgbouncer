import subprocess
import time

import psycopg
import pytest

from .utils import (
    DIRECT_TLS_SUPPORT,
    MACOS,
    PG_MAJOR_VERSION,
    PG_SUPPORTS_SCRAM,
    TEST_DIR,
    TLS_SUPPORT,
    WINDOWS,
    Bouncer,
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


@pytest.fixture
def rotating_server_tls(bouncer_tls, pg, cert_dir, tmp_path):
    """Real mTLS backend with stable, atomically replaceable credential paths."""
    ca = cert_dir / "TestCA1"
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    root = tmp_path / "ca.crt"
    cert.write_bytes((ca / "sites/02-bouncer.crt").read_bytes())
    key.write_bytes((ca / "sites/02-bouncer.key").read_bytes())
    root.write_bytes((ca / "ca.crt").read_bytes())
    key.chmod(0o600)
    renewed = tmp_path / "renewed.crt"
    subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(cert),
            "-CA",
            str(ca / "ca.crt"),
            "-CAkey",
            str(ca / "ca.key"),
            "-set_serial",
            "202",
            "-days",
            "30",
            "-out",
            str(renewed),
        ],
        check=True,
        capture_output=True,
    )
    pg.ssl_access("all", "cert")
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")
    pg.reload()
    bouncer_tls.default_db = "pTxnPool"
    bouncer_tls.ini_path.write_text(
        bouncer_tls.ini_path.read_text().replace("host=127.0.0.1", "host=localhost")
    )
    for setting, value in {
        "server_tls_sslmode": "verify-full",
        "server_tls_ca_file": root,
        "server_tls_cert_file": cert,
        "server_tls_key_file": key,
        "server_tls_reload_interval": "0.2",
    }.items():
        bouncer_tls.write_ini(f"{setting} = {value}")
    bouncer_tls.admin("RELOAD")
    return bouncer_tls, cert, key, root, renewed


def replace_tls_file(path, content):
    candidate = path.with_suffix(".candidate")
    candidate.write_bytes(content)
    candidate.chmod(0o600)
    candidate.replace(path)


def wait_for_tls_log(bouncer, offset, message):
    for _ in wait_until(message):
        if message in bouncer.log_path.read_text()[offset:]:
            return


def test_server_tls_auto_reload_transaction(rotating_server_tls):
    bouncer, cert, _key, _root, renewed = rotating_server_tls
    query = "SELECT pg_backend_pid(), client_serial::text FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
    with bouncer.conn() as conn:
        with conn.transaction():
            before = conn.execute(query).fetchone()
            offset = len(bouncer.log_path.read_text())
            replace_tls_file(cert, renewed.read_bytes())
            wait_for_tls_log(bouncer, offset, "server TLS files changed")
            assert conn.execute(query).fetchone() == before
        after = conn.execute(query).fetchone()
        assert after[0] != before[0]
        assert after[1] == "202"
        # Neither normal timer checks nor rewriting identical bytes churn pools.
        replace_tls_file(cert, renewed.read_bytes())
        time.sleep(0.8)
        assert conn.execute(query).fetchone() == after


@pytest.mark.parametrize("invalid", ["mismatch", "malformed", "missing", "ca"])
def test_server_tls_auto_reload_retains_snapshot(
    rotating_server_tls, cert_dir, invalid
):
    bouncer, cert, key, root, renewed = rotating_server_tls
    target = root if invalid == "ca" else key
    original = target.read_bytes()
    query = "SELECT pg_backend_pid(), client_serial::text FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
    with bouncer.conn() as conn:
        with conn.transaction():
            before = conn.execute(query).fetchone()
            offset = len(bouncer.log_path.read_text())
            if invalid == "missing":
                target.unlink()
            elif invalid == "mismatch":
                replace_tls_file(
                    key, (cert_dir / "TestCA1/sites/01-localhost.key").read_bytes()
                )
            else:
                replace_tls_file(target, b"not PEM\n")
            wait_for_tls_log(bouncer, offset, "ERROR")
            assert conn.execute(query).fetchone() == before
            # A second physical backend must use the retained memory snapshot,
            # rather than re-opening the now-invalid file.
            fresh = bouncer.sql(query)[0]
            assert fresh[0] != before[0]
            assert fresh[1] == before[1]
        offset = len(bouncer.log_path.read_text())
        replace_tls_file(target, original)
        replace_tls_file(cert, renewed.read_bytes())
        wait_for_tls_log(bouncer, offset, "server TLS files changed")
        assert conn.execute(query).fetchone()[1] == "202"


def test_server_tls_auto_reload_ca_only(rotating_server_tls, cert_dir):
    bouncer, _cert, _key, root, _renewed = rotating_server_tls
    query = "SELECT pg_backend_pid(), client_serial::text FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
    before = bouncer.sql(query)[0]
    offset = len(bouncer.log_path.read_text())
    replace_tls_file(
        root, root.read_bytes() + (cert_dir / "TestCA2/ca.crt").read_bytes()
    )
    wait_for_tls_log(bouncer, offset, "server TLS files changed")
    after = bouncer.sql(query)[0]
    assert before[0] != after[0]
    assert before[1] == after[1]


def test_server_tls_auto_reload_disable_and_enable(rotating_server_tls):
    bouncer, cert, _key, _root, renewed = rotating_server_tls
    query = "SELECT pg_backend_pid(), client_serial::text FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
    bouncer.admin("SET server_tls_reload_interval=0")
    with bouncer.conn() as conn:
        with conn.transaction():
            before = conn.execute(query).fetchone()
            replace_tls_file(cert, renewed.read_bytes())
            time.sleep(0.8)
            assert conn.execute(query).fetchone() == before
            # Disabled: legacy new-connection file reads are preserved.
            assert bouncer.sql(query)[0][1] == "202"
        assert conn.execute(query).fetchone() == before
        bouncer.admin("SET server_tls_reload_interval='0.2'")
        after = conn.execute(query).fetchone()
        assert after[0] != before[0]
        assert after[1] == "202"
