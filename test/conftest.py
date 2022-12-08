import pytest
from .utils import *


def pgctl(command, **kwargs):
    run(
        f"pg_ctl --wait --options '-p {PG_PORT}' --pgdata {PGDATA} --log {PG_LOG} {command}",
        **kwargs,
    )


@pytest.fixture(autouse=True, scope="session")
def pg():
    LOGDIR.mkdir(exist_ok=True)
    if PG_LOG.exists():
        PG_LOG.unlink()

    pg = Postgres(PGDATA, PG_PORT, PG_LOG)
    pg.initdb()

    pg.allow_local_access("p6", "scram-sha-256")
    pg.allow_local_access("p4", "password")
    pg.allow_local_access("p5", "md5")
    pg.allow_local_access("all", "trust")

    pg.start()
    for i in range(8):
        pg.sql(f"create database p{i}")

    pg.sql("create user bouncer")
    pg.sql("create user pswcheck with superuser createdb password 'pgbouncer-check';")
    pg.sql("create user someuser with password 'anypasswd';")
    pg.sql("create user maxedout;")
    pg.sql("create user maxedout2;")
    # cur.execute(f"create user longpass with password '{LONG_PASSWORD}';")
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

    yield pg

    pg.cleanup()


@pytest.fixture(autouse=True)
def bouncer():
    # By using --quiet we don't have to call .communicate() to clear OS buffers
    bouncer = Bouncer(BOUNCER_PORT)
    bouncer.start()

    yield bouncer

    bouncer.cleanup()


@pytest.fixture(autouse=True)
def pg_log():
    with PG_LOG.open() as f:
        f.seek(0, os.SEEK_END)
        yield
        print("\n\nPG_LOG\n")
        print(f.read())
