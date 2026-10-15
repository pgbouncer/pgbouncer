def test_repeated_pgbouncer_section_merges(bouncer):
    """
    A [pgbouncer] section that appears again later in the file adds to what the
    earlier block set, instead of resetting the settings it does not mention.
    """
    bouncer.write_ini("[pgbouncer]")
    bouncer.write_ini("max_client_conn = 77")
    bouncer.write_ini("[pgbouncer]")
    bouncer.write_ini("default_pool_size = 42")
    bouncer.admin("RELOAD")

    assert bouncer.config_value("max_client_conn") == "77"
    assert bouncer.config_value("default_pool_size") == "42"
    bouncer.test()


async def test_included_pgbouncer_section_merges(bouncer):
    """
    Splitting the configuration over %include files is the documented use for
    the directive, and the shipped pgbouncer.ini ends its [pgbouncer] section
    with a commented-out %include. So an included file that opens with its own
    [pgbouncer] header has to add to the including one, at startup as well as
    on RELOAD.

    The included file deliberately ends in a section other than the one it
    opened, so that the test can tell the two candidate behaviours apart. An
    %include does not restore the including file's section, which is why the
    lines after it here have to name their sections again; the [databases]
    entry placed straight after the %include pins that, since it would be an
    unknown [pgbouncer] parameter if the context were restored.
    """
    included = bouncer.config_dir / "included.ini"
    included.write_text("[pgbouncer]\nmax_client_conn = 77\n\n[databases]\n")

    bouncer.write_ini("[pgbouncer]")
    bouncer.write_ini(f"%include {included}")
    bouncer.write_ini(
        f"leaked_db = host={bouncer.pg.host} port={bouncer.pg.port} dbname=p0"
    )
    bouncer.write_ini("[pgbouncer]")
    bouncer.write_ini("default_pool_size = 42")
    bouncer.admin("RELOAD")

    assert bouncer.config_value("max_client_conn") == "77"
    assert bouncer.config_value("default_pool_size") == "42"
    assert "leaked_db" in [row[0] for row in bouncer.admin("SHOW DATABASES")]

    await bouncer.restart()

    assert bouncer.config_value("max_client_conn") == "77"
    assert bouncer.config_value("default_pool_size") == "42"
    assert "leaked_db" in [row[0] for row in bouncer.admin("SHOW DATABASES")]
    bouncer.test()


def test_reload_reverts_a_removed_setting(bouncer):
    """
    Re-entering a section used to re-apply the default of every key in it,
    which is how removing a setting from the file and reloading puts it back to
    its default. Applying the defaults on first entry only has to keep that
    working.
    """
    default_value = bouncer.config_value("max_db_connections")
    assert default_value != "7"

    bouncer.write_ini("[pgbouncer]")
    bouncer.write_ini("max_db_connections = 7")
    bouncer.admin("RELOAD")
    assert bouncer.config_value("max_db_connections") == "7"

    bouncer.reset_ini()
    bouncer.admin("RELOAD")
    assert bouncer.config_value("max_db_connections") == default_value
    bouncer.test()


def test_repeated_databases_users_and_peers_sections_are_allowed(bouncer):
    """
    [databases], [users] and [peers] set their keys through a callback, so they
    never had defaults to re-apply and repeating them has always been allowed.
    Splitting them over several blocks has to keep working.
    """
    bouncer.write_ini("[peers]")
    bouncer.write_ini(f"1 = host={bouncer.admin_host} port={bouncer.port}")
    bouncer.write_ini("[databases]")
    bouncer.write_ini(
        f"extra_db = host={bouncer.pg.host} port={bouncer.pg.port} dbname=p0"
    )
    bouncer.write_ini("[users]")
    bouncer.write_ini("extra_user = pool_size=3")
    bouncer.write_ini("[peers]")
    bouncer.write_ini(f"2 = host={bouncer.admin_host} port={bouncer.port}")
    bouncer.admin("RELOAD")

    databases = [row[0] for row in bouncer.admin("SHOW DATABASES")]
    assert "p0" in databases
    assert "extra_db" in databases
    assert "extra_user" in [row[0] for row in bouncer.admin("SHOW USERS")]
    assert [row[0] for row in bouncer.admin("SHOW PEERS")] == [1, 2]
    bouncer.test()
