import time

import psycopg
import pytest


def test_qa_gh001104(bouncer):
    """
    QA test for GitHub issue #1104 [PgCredentials objects are freed incorrectly]
    """

    def do_attempt(bouncer, passNum):
        config = f"""
            [databases]
        """

        n = 0
        while n < (10 * passNum):
            n = n + 1
            config += f"""
                testdb_{passNum}_{n} = host={bouncer.pg.host} port={bouncer.pg.port} user=dummy_user_{passNum}_{n}
            """

        config += f"""
            [pgbouncer]
            listen_addr = {bouncer.host}
            listen_port = {bouncer.port}

            auth_type = md5
            auth_file = {bouncer.auth_path}
            auth_query = SELECT usename, passwd FROM pg_shadow where usename = $1
            auth_user = postgres
            auth_dbname = postgres
            admin_users = pswcheck
            logfile = {bouncer.log_path}
        """

        with bouncer.run_with_config(config):
            bouncer.admin("RELOAD")  # again

    n = 0

    while n < 50:
        n = n + 1
        do_attempt(bouncer, n)
