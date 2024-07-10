import time

import psycopg
import pytest


def test_qa_gh001103__put_in_order__v01__get_pool(bouncer):
    """
    Check that the pgbouncer handles correctly multiple credentials with one name (isue #1103).
    """

    config = f"""
        [databases]
        * = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres min_pool_size=2
        [pgbouncer]
        listen_addr = {bouncer.host}
        listen_port = {bouncer.port}

        auth_type = trust
        auth_file = {bouncer.auth_path}
        auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
        auth_user = postgres
        auth_dbname = postgres
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
    """

    with bouncer.run_with_config(config):
        # Let's get an error "no such user"
        print("POINT #001")
        with pytest.raises(psycopg.OperationalError, match="no such user"):
            bouncer.conn(dbname="dummydb2", user="dummyuser2", password="dummypswd2")
        # Let's wait a few seconds to allow pgbouncer to crash in put_in_order
        time.sleep(5)
        # Now we will try to connect with OK parameters
        print("POINT #002")
        with bouncer.conn(dbname="p3", user="postgres", password="asdasd") as cn:
            with cn.cursor() as cur:
                cur.execute("select 1")

    print("OK!")
