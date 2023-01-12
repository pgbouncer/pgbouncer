import pytest
import os
import filelock
import shutil
from .utils import *


def create_certs(cert_dir):
    run(
        "sh create_certs.sh",
        cwd=TEST_DIR / "ssl",
        silent=True,
    )
    cert_dir.mkdir()
    shutil.move(TEST_DIR / "ssl" / "TestCA1", cert_dir / "TestCA1")
    shutil.move(TEST_DIR / "ssl" / "TestCA2", cert_dir / "TestCA2")


@pytest.fixture(autouse=True, scope="session")
def cert_dir(tmp_path_factory, worker_id):
    """Creates certificates in a shared temporary directory

    This cert directory is shared by all concurrent test processes
    """
    if not TLS_SUPPORT:
        return None
    # get the temp directory shared by all workers
    if worker_id == "master":
        # not executing in with multiple workers, just produce the data and let
        # pytest's fixture caching do its job
        cert_dir = tmp_path_factory.getbasetemp() / "certs"
        create_certs(cert_dir)
    else:
        root_tmp_dir = tmp_path_factory.getbasetemp().parent
        cert_dir = root_tmp_dir / "certs"
        with filelock.FileLock(str(cert_dir) + ".lock"):
            if not cert_dir.is_dir():
                create_certs(cert_dir)
    return cert_dir


@pytest.fixture(autouse=True, scope="session")
def pg(tmp_path_factory, cert_dir):
    """Starts a new Postgres db that is shared for tests in this process"""
    pg = Postgres(tmp_path_factory.getbasetemp() / "pgdata")
    pg.initdb()
    os.truncate(pg.hba_path, 0)

    if TLS_SUPPORT:
        with pg.conf_path.open("a") as f:
            cert = cert_dir / "TestCA1" / "sites" / "01-localhost.crt"
            key = cert_dir / "TestCA1" / "sites" / "01-localhost.key"
            f.write(f"ssl_cert_file='{cert}'\n")
            f.write(f"ssl_key_file='{key}'\n")

    pg.nossl_access("all", "trust")
    pg.nossl_access("p4", "password")
    pg.nossl_access("p5", "md5")
    if PG_SUPPORTS_SCRAM:
        pg.nossl_access("p6", "scram-sha-256")
    pg.commit_hba()

    pg.start()
    for i in range(8):
        pg.sql(f"create database p{i}")

    pg.sql("create user bouncer")
    pg.sql("create user pswcheck with superuser createdb password 'pgbouncer-check';")
    pg.sql("create user someuser with password 'anypasswd';")
    pg.sql("create user maxedout;")
    pg.sql("create user maxedout2;")
    pg.sql(f"create user longpass with password '{LONG_PASSWORD}';")
    if PG_SUPPORTS_SCRAM:
        pg.sql("set password_encryption = 'md5'; create user muser1 password 'foo';")
        pg.sql("set password_encryption = 'md5'; create user muser2 password 'wrong';")
        pg.sql("set password_encryption = 'md5'; create user puser1 password 'foo';")
        pg.sql("set password_encryption = 'md5'; create user puser2 password 'wrong';")
        pg.sql(
            "set password_encryption = 'scram-sha-256'; create user scramuser1 password '"
            "SCRAM-SHA-256$4096:D76gvGUVj9Z4DNiGoabOBg==$RukL0Xo3Ql/2F9FsD7mcQ3GATG2fD3PA71qY1JagGDs=:BhKUwyyivFm7Tq2jDJVXSVRbRDgTWyBilZKgg6DDuYU="
            "'"
        )
        pg.sql(
            "set password_encryption = 'scram-sha-256'; create user scramuser3 password 'baz';"
        )
    else:
        pg.sql("set password_encryption = 'on'; create user muser1 password 'foo';")
        pg.sql("set password_encryption = 'on'; create user muser2 password 'wrong';")
        pg.sql("set password_encryption = 'on'; create user puser1 password 'foo';")
        pg.sql("set password_encryption = 'on'; create user puser2 password 'wrong';")

    yield pg

    pg.cleanup()


@pytest.mark.asyncio
@pytest.fixture
async def bouncer(pg, tmp_path):
    """Starts a new PgBouncer process"""
    bouncer = Bouncer(pg, tmp_path / "bouncer")

    await bouncer.start()

    yield bouncer

    await bouncer.cleanup()


@pytest.fixture(autouse=True)
def pg_log(pg):
    """Prints the Postgres logs that were created during the test

    This can be useful for debugging a failure.
    """
    with pg.log_path.open() as f:
        f.seek(0, os.SEEK_END)
        yield
        print("\n\nPG_LOG\n")
        print(f.read())


@pytest.fixture(autouse=True)
def pg_reset(pg):
    """Resets any changes to Postgres settings from previous tests"""
    pg.reset_hba()
    os.truncate(pg.pgdata / "postgresql.auto.conf", 0)
    pg.reload()

    yield
