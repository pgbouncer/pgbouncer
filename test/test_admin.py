from psycopg.rows import dict_row

from .utils import capture, run, Bouncer

from configparser import ConfigParser


def test_show(bouncer):
    show_items = [
        "clients",
        "config",
        "databases",
        # Calling SHOW FDS on MacOS leaks the returned file descriptors to the
        # python test runner. So we don't test this one directly. SHOW FDS is
        # still tested indirectly by the takeover tests.
        # "fds",
        "help",
        "lists",
        "peers",
        "peer_pools",
        "pools",
        "servers",
        "sockets",
        "active_sockets",
        "state",
        "stats",
        "stats_totals",
        "stats_averages",
        "users",
        "totals",
        "mem",
        "dns_hosts",
        "dns_zones",
    ]

    for item in show_items:
        bouncer.admin(f"SHOW {item}")


def test_show_version(bouncer):
    admin_version = bouncer.admin_value(f"SHOW VERSION")
    subprocess_result = capture(
        [*bouncer.base_command(), "--version"],
    )
    subprocess_version = subprocess_result.split("\n")[0]
    assert admin_version == subprocess_version


def test_help(bouncer):
    run([*bouncer.base_command(), "--help"])


def test_show_stats(bouncer):
    # Use session pooling database to see differenecs between transactions and
    # server assignments
    bouncer.default_db = "p3"
    bouncer.test()
    bouncer.test()
    bouncer.test()
    bouncer.test()
    with bouncer.cur() as cur:
        with cur.connection.transaction():
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")
        with cur.connection.transaction():
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")
            cur.execute("SELECT 1")

    stats = bouncer.admin("SHOW STATS", row_factory=dict_row)
    p3_stats = next(s for s in stats if s["database"] == "p3")
    assert p3_stats is not None
    # 5 connection attempts (and thus assignments)
    assert p3_stats["total_server_assignment_count"] == 5
    # 4 autocommit queries + 2 transactions
    assert p3_stats["total_xact_count"] == 6
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK
    assert p3_stats["total_query_count"] == 15

    stats = bouncer.admin("SHOW STATS_TOTALS", row_factory=dict_row)
    p3_stats = next(s for s in stats if s["database"] == "p3")
    assert p3_stats is not None
    # 5 connection attempts (and thus assignments)
    assert p3_stats["server_assignment_count"] == 5
    # 4 autocommit queries + 2 transactions
    assert p3_stats["xact_count"] == 6
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK
    assert p3_stats["query_count"] == 15

    totals = bouncer.admin("SHOW TOTALS")
    # 5 connection attempts (and thus assignments)
    assert ("total_server_assignment_count", 5) in totals
    # 4 autocommit queries + 2 transactions + 4 admin commands
    assert ("total_xact_count", 10) in totals
    # 11 SELECT 1 + 2 times COMMIT and ROLLBACK + 4 admin commands
    assert ("total_query_count", 19) in totals


def test_reload_and_check_dbs(bouncer: Bouncer):
    # This test changes database list in INI file, reloads pgbouncer
    # and checks actual databases
    C_INI_SECTION__DATABASES = "databases"

    def reload_and_check(bouncer: Bouncer, config: ConfigParser):
        with open(bouncer.ini_path, "w") as configfile:
            config.write(configfile)

        bouncer.admin("RELOAD")
        cur_dbs = bouncer.admin("SHOW DATABASES", row_factory=dict_row)

        expected_dbs = []
        for x in config.options(C_INI_SECTION__DATABASES):
            expected_dbs.append(x)

        actual_dbs = []
        for x in cur_dbs:
            actual_dbs.append(x["name"])

        # Try to find all expected databases
        for x in expected_dbs:
            assert x in actual_dbs

        # Verification of all the actual databases
        has_pgbouncer_db = False
        for x in actual_dbs:
            if x == "pgbouncer":
                has_pgbouncer_db = True
            else:
                assert x in expected_dbs
        assert has_pgbouncer_db

    config = ConfigParser(strict=False)
    iniFile = bouncer.ini_path
    config.read(iniFile)
    dbs = {}
    for x in config.options(C_INI_SECTION__DATABASES):
        dbs[x] = config.get(C_INI_SECTION__DATABASES, x)

    # Removing databases
    for db_name in dbs:
        config.remove_option(C_INI_SECTION__DATABASES, db_name)
        reload_and_check(bouncer, config)

    # Appending databases
    for db_name in dbs:
        config.set(C_INI_SECTION__DATABASES, db_name, dbs[db_name])
        reload_and_check(bouncer, config)
