import asyncio
import re
import time

import psycopg
import pytest

from .utils import HAVE_IPV6_LOCALHOST


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


def test_track_startup_parameters(bouncer):
    # test.ini has track_startup_parameters set to a list of Postgres
    # parameters. Test that the parameters in the list in addition to the
    # default hardcoded list of parameters are cached per client.
    bouncer.admin(f"set pool_mode=transaction")

    test_set = {
        "intervalstyle" : ["sql_standard", "postgres"],
        "standard_conforming_strings" : ["ON", "OFF"],
        "timezone" : ["'Europe/Amsterdam'", "'Europe/Rome'"],
        "client_encoding" : ["ISO_8859_7", "LATIN5"],
        "datestyle" : ["PostgreSQL,European", "ISO,US"],
        "application_name" : ["client1", "client2"],
    }

    test_expected = {
        "intervalstyle" : ["sql_standard", "postgres"],
        "standard_conforming_strings" : ["on", "off"],
        "timezone" : ["Europe/Amsterdam", "Europe/Rome"],
        "client_encoding" : ["ISO_8859_7", "LATIN5"],
        "datestyle" : ["Postgres, DMY",  "ISO, MDY"],
        "application_name" : ["client1", "client2"],
    }

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
