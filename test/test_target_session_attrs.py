import psycopg
import pytest

from .utils import MACOS, PG_MAJOR_VERSION, USE_SUDO, Bouncer

if PG_MAJOR_VERSION < 14:
    pytest.skip(
        "target_session_attrs only supported on PG 14+", allow_module_level=True
    )


@pytest.fixture(autouse=True)
def skip_if_macos_and_no_sudo():
    # The replica Postgres instance needs to bind to another IPv4 address
    if MACOS and not USE_SUDO:
        pytest.skip("localhost only binds to 127.0.0.1/32 by default on MACOS")
    else:
        yield


@pytest.fixture(autouse=True)
def setup_test_target_session_attrs(bouncer):
    bouncer.admin(f"set server_login_retry=1")
    bouncer.admin(f"set client_login_timeout=5")


@pytest.fixture
def bouncer_transaction_read_only(bouncer):
    bouncer.pg.psql("ALTER DATABASE p0 SET default_transaction_read_only=on")
    yield bouncer
    bouncer.pg.psql("ALTER DATABASE p0 SET default_transaction_read_only=off")


def test_target_session_attrs_primary_first(bouncer, replica):
    with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 1):
        bouncer.test(dbname="primary_first")


def test_target_session_attrs_primary_second(bouncer, replica):
    with bouncer.log_contains(
        r"127.0.0.2:\d+ closing because: server does not satisfy target_session_attrs",
        1,
    ):
        bouncer.test(dbname="primary_second")


def test_target_session_attrs_standby_first(bouncer, replica):
    with bouncer.log_contains(r"127.0.0.2:\d+ new connection to server", 1):
        bouncer.test(dbname="standby_first")


def test_target_session_attrs_standby_second(bouncer, replica):
    with bouncer.log_contains(
        r"127.0.0.1:\d+ closing because: server does not satisfy target_session_attrs",
        1,
    ):
        bouncer.test(dbname="standby_second")


def test_target_session_attrs_readonly_first(bouncer, replica):
    with bouncer.log_contains(r"127.0.0.2:\d+ new connection to server", 1):
        bouncer.test(dbname="readonly_first")


def test_target_session_attrs_readonly_second(bouncer, replica):
    with bouncer.log_contains(
        r"127.0.0.1:\d+ closing because: server does not satisfy target_session_attrs",
        1,
    ):
        bouncer.test(dbname="readonly_second")


def test_target_session_attrs_readonly_primary_in_transaction_read_only_first(
    bouncer_transaction_read_only, replica
):
    with bouncer_transaction_read_only.log_contains(
        r"127.0.0.1:\d+ closing because: server does not satisfy target_session_attrs",
        times=0,
    ):
        bouncer_transaction_read_only.test(dbname="readonly_second")


def test_target_session_attrs_readwrite_first(bouncer, replica):
    with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 1):
        bouncer.test(dbname="readwrite_first")


def test_target_session_attrs_readwrite_second(bouncer, replica):
    with bouncer.log_contains(
        r"127.0.0.2:\d+ closing because: server does not satisfy target_session_attrs",
        1,
    ):
        bouncer.test(dbname="readwrite_second")


def test_target_session_attrs_any_primary_first(bouncer, replica):
    with bouncer.log_contains(r"127.0.0.1:\d+ new connection to server", 1):
        bouncer.test(dbname="any_primary_first")


def test_target_session_attrs_any_primary_second(bouncer, replica):
    with bouncer.log_contains(r"127.0.0.2:\d+ new connection to server", 1):
        bouncer.test(dbname="any_primary_second")


@pytest.mark.asyncio
async def test_target_session_attrs_with_readonly_vars(bouncer, replica):
    with bouncer.log_contains(r'ERROR varcache_apply failed: ERROR: parameter "in_hot_standby" cannot be changed', 0):
        try:
            # Execute two concurrent sleeps to force two backend connections.
            await bouncer.asleep(dbname="multiple_hosts", duration=0.5, times=2)
        except psycopg.OperationalError:
            pytest.fail("Unexpected error connecting to pgbouncer with multiple hosts")
