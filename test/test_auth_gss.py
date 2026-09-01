import os
import socket
import subprocess

import psycopg
import pytest

from .utils import GSS_SUPPORT

REALM = "EXAMPLE.COM"
KADMIN_PRINCIPAL = "root"
MASTER_PASSWORD = "master_password"
KADMIN_PASSWORD = "root"

if "REALM" in os.environ:
    REALM = os.environ["REALM"]

if "KADMIN_PASSWORD" in os.environ:
    KADMIN_PASSWORD = os.environ["KADMIN_PASSWORD"]

KADMIN_PRINCIPAL_FULL = f"root@{REALM}"
USER_SWAPPED_CASE = f"ROOT@{REALM}"
REALM_SWAPPED_CASE = f"root@{REALM.swapcase()}"


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_hba(bouncer_with_krb5):

    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = hba
        admin_users = pgbouncer
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
    """
    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_default_behavior(bouncer_with_krb5):
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        admin_users = pgbouncer
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
    """
    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_case_sensitive_negative(bouncer_with_krb5):
    """
    Test that user fails when there is a mismatch on name due to case issues
    """
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer_with_krb5.auth_path}
        admin_users = pgbouncer
        listen_port = {bouncer_with_krb5.port}
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
    """

    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        with pytest.raises(psycopg.OperationalError, match="GSS authentication failed"):
            bouncer_with_krb5.test(user=USER_SWAPPED_CASE, dbname="postgres", gssencmode="disable", require_auth="gss")
    bouncer_with_krb5.krb5.kdestroy()


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_case_insensitive_positive(bouncer_with_krb5):
    """
    Test that user is accepted when there is a match on name even with casing issues
    """
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer_with_krb5.auth_path}
        admin_users = pgbouncer
        listen_port = {bouncer_with_krb5.port}
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_krb_caseins_users = 1
    """
    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.test(user=USER_SWAPPED_CASE, dbname="postgres", gssencmode="disable", require_auth="gss")
    bouncer_with_krb5.krb5.kdestroy()


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_realm_match_case_sensitive_negative(bouncer_with_krb5):
    """
    Test that realm is matched for case sesativity when using bouncer wide config
    """
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        admin_users = pgbouncer
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
        auth_gss_parameter = krb_realm={REALM.swapcase()}
    """
    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="GSS authentication failed"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
    bouncer_with_krb5.krb5.kdestroy()


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_realm_match_case_sensitive_positive(bouncer_with_krb5):
    """
    Test that realm match functions when used in bouncer wide config
    """
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer_with_krb5.auth_path}
        admin_users = pgbouncer
        listen_port = {bouncer_with_krb5.port}
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
        auth_gss_parameter = krb_realm={REALM}
    """
    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_realm_match_case_insensitive_negative(bouncer_with_krb5):
    """
    Test that realm match works in bouncer wide config when used with case
    insensitive mode.
    """
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        admin_users = pgbouncer
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
        auth_krb_caseins_users = 1
        auth_gss_parameter = krb_realm={REALM.swapcase()}a
    """
    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="GSS authentication failed"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_realm_match_case_insensitive_positive(bouncer_with_krb5):
    """
    Test that realm match mode correctly accepts match even with differences
    in case.
    """
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        admin_users = pgbouncer
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
        auth_krb_caseins_users = 1
        auth_gss_parameter = krb_realm={REALM.swapcase()}
    """
    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_hba_case_insensitive_positive_realm_match(bouncer_with_krb5):
    """
    Test that user is accepted even with case sensativity issues when using HBA
    realm checking.
    """
    hba_conf_file = bouncer_with_krb5.config_dir / "hba.conf"
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = hba
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        admin_users = pgbouncer
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_krb_caseins_users = 1
        auth_hba_file = {hba_conf_file}
    """
    bouncer_with_krb5.krb5.kinit()
    with open(hba_conf_file, "w") as f:
        hba_entry = [
            "host",
            "postgres",
            KADMIN_PRINCIPAL_FULL,
            "0.0.0.0/0",
            "gss",
            f"krb_realm={REALM.swapcase()}",
        ]
        f.write(" ".join(hba_entry))
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_hba_case_sensitive_negative_realm_match(bouncer_with_krb5):
    """
    Test that user is rejected when using case insesitive realm match with HBA
    """
    hba_conf_file = bouncer_with_krb5.config_dir / "hba.conf"

    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = hba
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        logfile = {bouncer_with_krb5.log_path}
        admin_users = pgbouncer
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_hba_file = {hba_conf_file}
    """

    with open(hba_conf_file, "w") as f:
        hba_entry = [
            "host",
            "postgres",
            KADMIN_PRINCIPAL_FULL,
            "0.0.0.0/0",
            "gss",
            f"krb_realm={REALM.swapcase()}",
        ]
        f.write(" ".join(hba_entry))

    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="GSS authentication failed"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres", gssencmode="disable", require_auth="gss")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_include_realm_disabled(bouncer_with_krb5):
    """
    Test include realm functionality for bouncer wide gss config
    """
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        admin_users = pgbouncer
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_gss_parameter = include_realm=0
    """
    bouncer_with_krb5.krb5.kinit()
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user="root", dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user="root", dbname="postgres", gssencmode="disable", require_auth="gss")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_hba_include_realm_disabled(bouncer_with_krb5):
    """
    Test include realm functionality for HBA config
    """
    hba_conf_file = bouncer_with_krb5.config_dir / "hba.conf"
    config = f"""
        [databases]
        postgres = host={bouncer_with_krb5.pg.host} port={bouncer_with_krb5.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = hba
        auth_file = {bouncer_with_krb5.auth_path}
        listen_port = {bouncer_with_krb5.port}
        admin_users = pgbouncer
        logfile = {bouncer_with_krb5.log_path}
        auth_krb_server_keyfile = {bouncer_with_krb5.krb5.keytab_fp}
        auth_hba_file = {hba_conf_file}
    """
    bouncer_with_krb5.krb5.kinit()
    with open(hba_conf_file, "w") as f:
        hba_entry = [
            "host",
            "postgres",
            "root",
            "0.0.0.0/0",
            "gss",
            "include_realm=0",
        ]
        f.write(" ".join(hba_entry))
    with bouncer_with_krb5.run_with_config(config):
        bouncer_with_krb5.test(user="root", dbname="postgres", gssencmode="disable", require_auth="gss")
        bouncer_with_krb5.krb5.kdestroy()
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer_with_krb5.test(user="root", dbname="postgres", gssencmode="disable", require_auth="gss")
