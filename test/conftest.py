import os
import shutil

import filelock
import pytest

from .utils import (
    LINUX,
    LONG_PASSWORD,
    PG_SUPPORTS_SCRAM,
    TEST_DIR,
    TLS_SUPPORT,
    USE_SUDO,
    Bouncer,
    Postgres,
    Proxy,
    run,
    sudo,
)


def add_qdisc():
    if not LINUX or not USE_SUDO:
        return
    # Add the all zeros priomap to prio so all regular traffic flows
    # through a single band. By default prio assigns traffic to different
    # band according to the DSCP value of the packet. This means that some
    # traffic that doesn't match your filter might end up in the same class
    # as the delayed traffic.
    # Source: https://stackoverflow.com/a/40203517/2570866
    sudo(
        "tc qdisc add dev lo root handle 1: prio bands 2 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    )
    # Add one band with additional latency
    sudo("tc qdisc add dev lo parent 1:2 handle 20: netem delay 1000ms")


def delete_qdisc():
    if not LINUX or not USE_SUDO:
        return
    sudo("tc qdisc del dev lo parent 1:2 handle 20:")
    sudo("tc qdisc del dev lo root")


def create_certs(cert_dir):
    run(
        "sh create_certs.sh",
        cwd=TEST_DIR / "ssl",
        silent=True,
    )
    if not TLS_SUPPORT:
        return

    cert_dir.mkdir()
    shutil.move(TEST_DIR / "ssl" / "TestCA1", cert_dir / "TestCA1")
    shutil.move(TEST_DIR / "ssl" / "TestCA2", cert_dir / "TestCA2")


@pytest.fixture(autouse=True, scope="session", name="cert_dir")
def shared_setup(tmp_path_factory, worker_id):
    """Does some setup that's shared between workers

    This setup should only be done once and should only be cleaned up once, at
    the end of the last finished worker process.

    It currently sets up 2 things:
    1. A cert directory, for TLS tests
    2. A queueing disciplines (qdisc), for tests that require latency

    It yields the certificate directory, which is why the fixture name is
    cert_dir.
    """
    if worker_id == "master":
        # not executing in with multiple workers, just do the setup without any
        # file locking.
        cert_dir = tmp_path_factory.getbasetemp() / "certs"
        add_qdisc()
        create_certs(cert_dir)
        yield cert_dir
        delete_qdisc()
        return

    total_workers = int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", ""))

    # get the temp directory shared by all workers
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    cert_dir = root_tmp_dir / "certs"
    lock_name = root_tmp_dir / "worker.lock"
    finished_count_file = root_tmp_dir / "finished_workers"
    with filelock.FileLock(lock_name):
        if not cert_dir.is_dir():
            finished_count_file.write_text("0")
            add_qdisc()
            create_certs(cert_dir)
    try:
        yield cert_dir
    finally:
        with filelock.FileLock(lock_name):
            finished_count = int(finished_count_file.read_text()) + 1
            if finished_count == total_workers:
                delete_qdisc()
            else:
                finished_count_file.write_text(str(finished_count))


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

    pg.nossl_access("replication", "trust", user="postgres")
    pg.nossl_access("all", "trust")
    pg.nossl_access("p4", "password")
    pg.nossl_access("p5", "md5")
    if PG_SUPPORTS_SCRAM:
        pg.nossl_access("p6", "scram-sha-256")
    pg.commit_hba()

    pg.start()
    for i in range(8):
        pg.sql(f"create database p{i}")

    pg.sql("create database unconfigured_auth_database")
    pg.sql("create user bouncer")

    pg.sql("create user pswcheck_not_in_auth_file with superuser;")
    pg.sql("create user pswcheck with superuser createdb password 'pgbouncer-check';")
    pg.sql("create user someuser with password 'anypasswd';")
    pg.sql("create user maxedout;")
    pg.sql("create user maxedout2;")
    pg.sql("create user maxedout3;")
    pg.sql("create user maxedout4;")
    pg.sql("create user maxedout5;")
    pg.sql("create user poolsize1;")
    pg.sql("create user respoolsize1;")
    pg.sql("create user test_error_message_user;")
    pg.sql(f"create user longpass with password '{LONG_PASSWORD}';")
    pg.sql("create user stats password 'stats';")
    pg.sql("grant all on schema public to public", dbname="p0")
    pg.sql("create table test_copy(i int)", dbname="p0")
    pg.sql("grant all on table test_copy to public", dbname="p0")

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
async def proxy(pg, tmp_path):
    """Starts a new proxy process"""
    proxy = Proxy(pg)

    proxy.start()

    yield proxy

    proxy.cleanup()


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

    # If a previous test restarted postgres, it was probably because of some
    # config that could only be changed across restarts. To reset those, we'll
    # have to restart it again. In other cases a reload should be enough to
    # reset the configuration.
    if pg.restarted:
        pg.restart()
        pg.restarted = False
    else:
        pg.reload()

    yield
