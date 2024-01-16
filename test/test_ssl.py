import subprocess

import psycopg
import pytest

from .utils import PG_MAJOR_VERSION, TEST_DIR, TLS_SUPPORT, WINDOWS, Bouncer

if not TLS_SUPPORT:
    pytest.skip(allow_module_level=True)

# XXX: These test use psql to connect using sslmode=verify-full instead of
# using psycopg. The reason for this is that psycopg has a bug on Apple
# silicon when enabling SSL: https://github.com/psycopg/psycopg/discussions/270


# override regular bouncer fixture with one that uses the special SSL config
@pytest.mark.asyncio
@pytest.fixture
async def bouncer(pg, tmp_path):
    bouncer = Bouncer(
        pg, tmp_path / "bouncer", base_ini_path=TEST_DIR / "ssl" / "test.ini"
    )

    await bouncer.start()

    yield bouncer

    await bouncer.cleanup()


def test_server_ssl(pg, bouncer, cert_dir):
    bouncer.admin("set server_tls_sslmode = require")
    pg.ssl_access("all", "trust")
    pg.configure("ssl=on")
    root = cert_dir / "TestCA1" / "ca.crt"
    pg.configure(f"ssl_ca_file='{root}'")
    print("ARE WE WINDOWS?", WINDOWS)
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
    bouncer.test()


def test_server_ssl_set_disable(pg, bouncer, cert_dir):
    bouncer.admin("set server_tls_sslmode = require")
    pg.ssl_access("all", "trust")
    pg.configure("ssl=on")
    root = cert_dir / "TestCA1" / "ca.crt"
    pg.configure(f"ssl_ca_file='{root}'")
    print("ARE WE WINDOWS?", WINDOWS)
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()

    bouncer.test()

    pg.reset_hba()
    print("ARE WE WINDOWS?", WINDOWS)
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
        bouncer.test()  # connection is still cached

    bouncer.admin("reconnect")
    with pytest.raises(
        psycopg.OperationalError,
        match="no pg_hba.conf entry for .*, (SSL encryption|SSL on)",
    ):
        bouncer.test()
    # XXX: It would be nice if this reset server_login_retry, but it currently
    # doesn't. So we have server_login_retry=1 in the ini file.
    bouncer.admin("set server_tls_sslmode = disable")
    bouncer.test()


def test_server_ssl_set_enable(pg, bouncer, cert_dir):
    bouncer.admin("set server_tls_sslmode = disable")
    pg.configure("ssl=on")
    root = cert_dir / "TestCA1" / "ca.crt"
    pg.configure(f"ssl_ca_file='{root}'")
    print("ARE WE WINDOWS?", WINDOWS)
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()

    bouncer.test()

    pg.nossl_access("all", "reject")
    pg.ssl_access("all", "trust")
    print("ARE WE WINDOWS?", WINDOWS)
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
        bouncer.test()  # connection is still cached

    bouncer.admin("reconnect")
    with pytest.raises(
        psycopg.OperationalError,
        match="pg_hba.conf rejects connection for .*, (no encryption|SSL off)",
    ):
        bouncer.test()

    # XXX: It would be nice if this reset server_login_retry, but it currently
    # doesn't. So we have server_login_retry=1 in the ini file.
    bouncer.admin("set server_tls_sslmode = require")
    bouncer.test()


def test_server_ssl_verify(pg, bouncer, cert_dir):
    bouncer.admin("set server_tls_sslmode = 'verify-full'")
    root = cert_dir / "TestCA1" / "ca.crt"
    wrong_root = cert_dir / "TestCA2" / "ca.crt"
    bouncer.admin(f"set server_tls_ca_file = '{wrong_root}'")
    pg.ssl_access("all", "trust")
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")
    print("ARE WE WINDOWS?", WINDOWS)
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
    with bouncer.log_contains(r"certificate verify failed"):
        with pytest.raises(
            psycopg.OperationalError,
            match="connection timeout expired",
        ):
            bouncer.test(connect_timeout=4)
    bouncer.admin(f"set server_tls_ca_file = '{root}'")
    bouncer.test()


def test_server_ssl_auth(pg, bouncer, cert_dir):
    bouncer.admin("set server_tls_sslmode = 'verify-full'")
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "02-bouncer.key"
    cert = cert_dir / "TestCA1" / "sites" / "02-bouncer.crt"
    bouncer.admin(f"set server_tls_ca_file = '{root}'")
    bouncer.admin(f"set server_tls_key_file = '{key}'")
    bouncer.admin(f"set server_tls_cert_file = '{cert}'")
    pg.ssl_access("all", "cert")
    pg.configure("ssl=on")
    pg.configure(f"ssl_ca_file='{root}'")
    if PG_MAJOR_VERSION < 10 or WINDOWS:
        pg.restart()
    else:
        pg.reload()
    bouncer.test()


def test_client_ssl(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.admin(f"set client_tls_key_file = '{key}'")
    bouncer.admin(f"set client_tls_cert_file = '{cert}'")
    bouncer.admin(f"set client_tls_ca_file = '{root}'")
    bouncer.admin(f"set client_tls_sslmode = require")
    bouncer.psql_test(host="localhost", sslmode="require")


def test_client_ssl_set_enable_disable(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.admin(f"set client_tls_key_file = '{key}'")
    bouncer.admin(f"set client_tls_cert_file = '{cert}'")
    bouncer.admin(f"set client_tls_ca_file = '{root}'")
    bouncer.admin(f"set client_tls_sslmode = require")
    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    bouncer.admin(f"set client_tls_sslmode = disable")
    bouncer.test(sslmode="disable")

    bouncer.admin(f"set client_tls_sslmode = require")
    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)


def test_client_ssl_set_change_ca(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.admin(f"set client_tls_key_file = '{key}'")
    bouncer.admin(f"set client_tls_cert_file = '{cert}'")
    bouncer.admin(f"set client_tls_ca_file = '{root}'")
    bouncer.admin(f"set client_tls_sslmode = require")
    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    new_root = cert_dir / "TestCA2" / "ca.crt"
    new_key = cert_dir / "TestCA2" / "sites" / "01-localhost.key"
    new_cert = cert_dir / "TestCA2" / "sites" / "01-localhost.crt"
    bouncer.admin(f"set client_tls_key_file = '{new_key}'")
    bouncer.admin(f"set client_tls_cert_file = '{new_cert}'")
    bouncer.admin(f"set client_tls_ca_file = '{new_root}'")

    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)
    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=new_root)


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_client_ssl_sighup_enable_disable(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.write_ini(f"client_tls_key_file = {key}")
    bouncer.write_ini(f"client_tls_cert_file = {cert}")
    bouncer.write_ini(f"client_tls_ca_file = {root}")
    bouncer.write_ini(f"client_tls_sslmode = require")
    bouncer.sighup()

    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    bouncer.write_ini(f"client_tls_sslmode = disable")
    bouncer.sighup()
    bouncer.test(sslmode="disable")


@pytest.mark.skipif("WINDOWS", reason="Windows does not have SIGHUP")
def test_client_ssl_sighup_change_ca(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.write_ini(f"client_tls_key_file = {key}")
    bouncer.write_ini(f"client_tls_cert_file = {cert}")
    bouncer.write_ini(f"client_tls_ca_file = {root}")
    bouncer.write_ini(f"client_tls_sslmode = require")
    bouncer.sighup()

    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    new_root = cert_dir / "TestCA2" / "ca.crt"
    new_key = cert_dir / "TestCA2" / "sites" / "01-localhost.key"
    new_cert = cert_dir / "TestCA2" / "sites" / "01-localhost.crt"
    bouncer.write_ini(f"client_tls_key_file = {new_key}")
    bouncer.write_ini(f"client_tls_cert_file = {new_cert}")
    bouncer.write_ini(f"client_tls_ca_file = {new_root}")
    bouncer.sighup()

    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)
    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=new_root)


def test_client_ssl_reload_enable_disable(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.write_ini(f"client_tls_key_file = {key}")
    bouncer.write_ini(f"client_tls_cert_file = {cert}")
    bouncer.write_ini(f"client_tls_ca_file = {root}")
    bouncer.write_ini(f"client_tls_sslmode = require")
    bouncer.admin("reload")

    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    bouncer.write_ini(f"client_tls_sslmode = disable")
    bouncer.admin("reload")
    bouncer.test(sslmode="disable")


def test_client_ssl_reload_change_ca(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.write_ini(f"client_tls_key_file = {key}")
    bouncer.write_ini(f"client_tls_cert_file = {cert}")
    bouncer.write_ini(f"client_tls_ca_file = {root}")
    bouncer.write_ini(f"client_tls_sslmode = require")
    bouncer.admin("reload")

    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)

    new_root = cert_dir / "TestCA2" / "ca.crt"
    new_key = cert_dir / "TestCA2" / "sites" / "01-localhost.key"
    new_cert = cert_dir / "TestCA2" / "sites" / "01-localhost.crt"
    bouncer.write_ini(f"client_tls_key_file = {new_key}")
    bouncer.write_ini(f"client_tls_cert_file = {new_cert}")
    bouncer.write_ini(f"client_tls_ca_file = {new_root}")
    bouncer.admin("reload")

    with pytest.raises(
        subprocess.CalledProcessError,
    ):
        bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=root)
    bouncer.psql_test(host="localhost", sslmode="verify-full", sslrootcert=new_root)


def test_client_ssl_auth(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.write_ini(f"client_tls_key_file = {key}")
    bouncer.write_ini(f"client_tls_cert_file = {cert}")
    bouncer.write_ini(f"client_tls_ca_file = {root}")
    bouncer.write_ini(f"client_tls_sslmode = verify-full")
    bouncer.write_ini(f"auth_type = cert")
    bouncer.admin("reload")

    client_key = cert_dir / "TestCA1" / "sites" / "02-bouncer.key"
    client_cert = cert_dir / "TestCA1" / "sites" / "02-bouncer.crt"
    bouncer.psql_test(
        host="localhost",
        sslmode="verify-full",
        user="bouncer",
        sslrootcert=root,
        sslkey=client_key,
        sslcert=client_cert,
    )


def test_client_ssl_scram(bouncer, cert_dir):
    root = cert_dir / "TestCA1" / "ca.crt"
    key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
    cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
    bouncer.write_ini(f"client_tls_key_file = {key}")
    bouncer.write_ini(f"client_tls_cert_file = {cert}")
    bouncer.write_ini(f"client_tls_ca_file = {root}")
    bouncer.write_ini(f"client_tls_sslmode = require")
    bouncer.write_ini(f"auth_type = scram-sha-256")
    bouncer.admin("reload")

    bouncer.psql_test(
        host="localhost",
        user="bouncer",
        password="zzzz",
        sslmode="verify-full",
        sslrootcert=root,
    )
