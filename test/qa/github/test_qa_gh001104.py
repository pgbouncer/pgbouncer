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

            auth_type = trust
            auth_file = {bouncer.auth_path}

            admin_users = pgbouncer

            logfile = {bouncer.log_path}
        """

        with bouncer.run_with_config(config):
            bouncer.admin("RELOAD")  # again

    n = 0
    while n < 15:
        n = n + 1
        print("ATTEMPT #", n)
        do_attempt(bouncer, n)
