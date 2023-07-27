import asyncio
import re
import time

import psycopg
import pytest

from .utils import HAVE_IPV6_LOCALHOST, WINDOWS


def test_connect_query(bouncer):
    # The p8 database definition in test.ini has some GUC settings
    # in connect_query.  Check that they get set.  (The particular
    # settings don't matter; just use some that are easy to set
    # and read.)

    assert bouncer.sql_value("show enable_seqscan", dbname="p8") == "off"
    assert bouncer.sql_value("show enable_nestloop", dbname="p8") == "off"


def test_fast_close(bouncer):
    with bouncer.cur(dbname="p3") as cur:
        cur.execute("select 1")
        bouncer.admin("set server_fast_close = 1")
        with bouncer.log_contains(r"closing because: database configuration changed"):
            bouncer.admin("reconnect p3")
            time.sleep(1)

            with pytest.raises(
                psycopg.OperationalError,
                match=r"server closed the connection unexpectedly|Software caused connection abort",
            ):
                cur.execute("select 1")


def test_track_extra_parameters(bouncer):
    # test.ini has track_extra_parameters set to a list of Postgres
    # parameters. Test that the parameters in the list in addition to the
    # default hardcoded list of parameters are cached per client.
    bouncer.admin(f"set pool_mode=transaction")

    test_set = {
        "intervalstyle": ["sql_standard", "postgres"],
        "standard_conforming_strings": ["ON", "OFF"],
        "timezone": ["'Europe/Amsterdam'", "'Europe/Rome'"],
        "datestyle": ["PostgreSQL,European", "ISO,US"],
        "application_name": ["client1", "client2"],
    }

    if not WINDOWS:
        test_set["client_encoding"] = ["LATIN1", "LATIN5"]

    test_expected = {
        "intervalstyle": ["sql_standard", "postgres"],
        "standard_conforming_strings": ["on", "off"],
        "timezone": ["Europe/Amsterdam", "Europe/Rome"],
        "datestyle": ["Postgres, DMY", "ISO, MDY"],
        "application_name": ["client1", "client2"],
    }

    if not WINDOWS:
        test_expected["client_encoding"] = ["LATIN1", "LATIN5"]

    with bouncer.cur(dbname="p1") as cur1:
        with bouncer.cur(dbname="p1") as cur2:
            for key in test_set:
                stmt1 = "SET " + key + " TO " + test_set[key][0]
                stmt2 = "SET " + key + " TO " + test_set[key][1]
                cur1.execute(stmt1)
                cur2.execute(stmt2)

                stmt = "SHOW " + key
                cur1.execute(stmt)
                cur2.execute(stmt)

                result1 = cur1.fetchone()
                assert result1[0] == test_expected[key][0]

                result2 = cur2.fetchone()
                assert result2[0] == test_expected[key][1]


@pytest.mark.asyncio
async def test_wait_close(bouncer):
    with bouncer.cur(dbname="p3") as cur:
        cur.execute("select 1")
        await bouncer.aadmin("reconnect p3")
        wait_close_task = bouncer.aadmin("wait_close p3")

        # We wait for 1 second to show that wait_close continues unless the
        # connection is closed.
        done, pending = await asyncio.wait([wait_close_task], timeout=1)
        assert done == set()
        assert pending == {wait_close_task}
    await wait_close_task


def test_auto_database(bouncer):
    with bouncer.ini_path.open() as f:
        original = f.read()
    with bouncer.ini_path.open("w") as f:
        # uncomment the auto-database line
        f.write(re.sub(r"^;\*", "*", original, flags=re.MULTILINE))

    bouncer.admin("reload")
    with bouncer.log_contains(r"registered new auto-database"):
        # p7 is not defined in test.ini
        bouncer.test(dbname="p7")


# This test checks database specifications with host lists.  The way
# we test this here is to have a host list containing an IPv4 and an
# IPv6 representation of localhost, and then we check the log that
# both connections were made.  Some CI environments don't have IPv6
# localhost configured.  Therefore, this test is skipped by default
# and needs to be enabled explicitly by setting HAVE_IPV6_LOCALHOST to
# non-empty.
@pytest.mark.asyncio
@pytest.mark.skipif("not HAVE_IPV6_LOCALHOST")
async def test_host_list(bouncer):
    with bouncer.log_contains(r"new connection to server \(from 127.0.0.1", times=1):
        with bouncer.log_contains(r"new connection to server \(from \[::1\]", times=1):
            await bouncer.asleep(1, dbname="hostlist1", times=2)


# This is the same test as above, except it doesn't use any IPv6
# addresses.  So we can't actually tell apart that two separate
# connections are made.  But the test is useful to get some test
# coverage (valgrind etc.) of the host list code on systems without
# IPv6 enabled.
@pytest.mark.asyncio
async def test_host_list_dummy(bouncer):
    with bouncer.log_contains(r"new connection to server \(from 127.0.0.1", times=2):
        await bouncer.asleep(1, dbname="hostlist2", times=2)


def test_options_startup_param(bouncer):
    assert (
        bouncer.sql_value("SHOW datestyle", options="  -c    datestyle=German,\\ YMD")
        == "German, YMD"
    )

    assert (
        bouncer.sql_value(
            "SHOW datestyle",
            options="-c timezone=Portugal  -c    datestyle=German,\\ YMD",
        )
        == "German, YMD"
    )

    assert (
        bouncer.sql_value(
            "SHOW timezone",
            options="-c timezone=Portugal  -c    datestyle=German,\\ YMD",
        )
        == "Portugal"
    )

    assert (
        bouncer.sql_value(
            "SHOW timezone", options="-ctimezone=Portugal  -cdatestyle=German,\\ YMD"
        )
        == "Portugal"
    )

    assert (
        bouncer.sql_value(
            "SHOW timezone",
            options="-c t\\imezone=\\P\\o\\r\\t\\ugal  -c    dat\\estyle\\=\\Ge\\rman,\\ YMD",
        )
        == "Portugal"
    )

    # extra_float_digits is in ignore_startup_parameters so setting it has no
    # effect, and the default of 1 will still be used.
    assert (
        bouncer.sql_value("SHOW extra_float_digits", options="-c extra_float_digits=2")
        == "1"
    )

    with pytest.raises(
        psycopg.OperationalError,
        match="unsupported options startup parameter: only '-c config=val' is allowed",
    ):
        bouncer.test(options="-d")

    with pytest.raises(
        psycopg.OperationalError,
        match="unsupported options startup parameter: only '-c config=val' is allowed",
    ):
        bouncer.test(options="-c timezone")

    too_long_param = "a" * 1000

    with pytest.raises(
        psycopg.OperationalError,
        match="unsupported options startup parameter: parameter too long",
    ):
        bouncer.test(options="-c timezone=" + too_long_param)

    with pytest.raises(
        psycopg.OperationalError,
        match="unsupported startup parameter in options: enable_seqscan",
    ):
        bouncer.test(options="-c enable_seqscan=false")

    bouncer.admin("set ignore_startup_parameters = options")
    # Unsupported values should be ignored, so it shouldn't error but it should
    # have its default value instead.
    assert (
        bouncer.sql_value(
            "SHOW enable_seqscan",
            options="-c enable_seqscan=false",
        )
        == "on"
    )

    # Even though we have options in ignore_startup_parameters, we still parse
    # and configure any values in it that we support
    assert (
        bouncer.sql_value(
            "SHOW timezone", options="-ctimezone=Portugal  -cdatestyle=German,\\ YMD"
        )
        == "Portugal"
    )
