import psycopg
import pytest

from .utils import PG_MAJOR_VERSION, Bouncer

if PG_MAJOR_VERSION < 14:
    pytest.skip(
        "target_session_attrs only supported on PG 14+", allow_module_level=True
    )


@pytest.fixture(autouse=True)
def setup_test_target_session_attrs(bouncer):
    bouncer.admin(f"set server_login_retry=1")
    bouncer.admin(f"set client_login_timeout=5")


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
