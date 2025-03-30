import getpass
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
KEYTAB_FILEPATH = "/tmp/pgbouncer.keytab"

if "KEYTAB_FILEPATH" in os.environ:
    KEYTAB_FILEPATH = os.environ["KEYTAB_FILEPATH"]

if "REALM" in os.environ:
    REALM = os.environ["REALM"]

if "KADMIN_PASSWORD" in os.environ:
    KADMIN_PASSWORD = os.environ["KADMIN_PASSWORD"]

KADMIN_PRINCIPAL_FULL = f"{getpass.getuser()}@{REALM}"
USER_SWAPPED_CASE = f"{getpass.getuser().swapcase()}@{REALM}"
REALM_SWAPPED_CASE = f"{getpass.getuser()}@{REALM.swapcase()}"


def setup_module(module):
    kerberos_command = f"""
    sudo krb5_newrealm <<EOF
    {MASTER_PASSWORD}
    {MASTER_PASSWORD}
    EOF
    """
    subprocess.run(kerberos_command, check=False, shell=True)

    delete_principal = f'sudo kadmin.local -q "delete_principal -force postgres"'
    subprocess.run(delete_principal, check=True, shell=True)
    delete_principal = f'sudo kadmin.local -q "delete_principal -force postgres/127.0.0.1"'
    subprocess.run(delete_principal, check=True, shell=True)

    create_principal = (
        f'sudo kadmin.local -q "addprinc -pw {KADMIN_PASSWORD} {KADMIN_PRINCIPAL_FULL}"'
    )
    subprocess.run(create_principal, check=True, shell=True)

    create_principal = 'sudo kadmin.local -q "addprinc -randkey postgres"'
    subprocess.run(create_principal, check=True, shell=True)

    create_principal = (
        f'sudo kadmin.local -q "addprinc -randkey postgres/127.0.0.1"'
    )
    subprocess.run(create_principal, check=True, shell=True)

    kadd_command = f'sudo kadmin.local -q "ktadd -k /tmp/pgbouncer.keytab postgres/127.0.0.1"'
    subprocess.run(kadd_command, check=True, shell=True)
    kadd_command_2 = 'sudo kadmin.local -q "ktadd -k /tmp/pgbouncer.keytab postgres"'
    subprocess.run(kadd_command_2, check=True, shell=True)

    change_permissions = "sudo chmod 644 /tmp/pgbouncer.keytab"
    subprocess.run(change_permissions, check=True, shell=True)


def teardown_module(module):
    subprocess.run("kdestroy", check=True, shell=True)

    delete_principal = (
        f'sudo kadmin.local -q "delete_principal -force {KADMIN_PRINCIPAL_FULL}"'
    )
    subprocess.run(delete_principal, check=True, shell=True)
    delete_principal = f'sudo kadmin.local -q "delete_principal -force postgres/127.0.0.1"'
    subprocess.run(delete_principal, check=True, shell=True)
    change_permissions = "sudo rm /tmp/pgbouncer.keytab"
    subprocess.run(change_permissions, check=True, shell=True)


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_hba(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = hba
        admin_users = pgbouncer
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_default_behavior(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        admin_users = pgbouncer
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_case_sensitive_negative(bouncer):
    """
    Test that user fails when there is a mismatch on name due to case issues
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer.auth_path}
        admin_users = pgbouncer
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
    """

    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        with pytest.raises(psycopg.OperationalError, match="GSS authentication failed"):
            bouncer.test(user=USER_SWAPPED_CASE, dbname="postgres")
    subprocess.run("kdestroy", check=True, shell=True)


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_case_insensitive_positive(bouncer):
    """
    Test that user is accepted when there is a match on name even with casing issues
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer.auth_path}
        admin_users = pgbouncer
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_krb_caseins_users = 1
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        bouncer.test(user=USER_SWAPPED_CASE, dbname="postgres")
    subprocess.run("kdestroy", check=True, shell=True)


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_realm_match_case_sensitive_negative(bouncer):
    """
    Test that realm is matched for case sesativity when using bouncer wide config
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
        auth_gss_parameter = krb_realm={REALM.swapcase()}
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="GSS authentication failed"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
    subprocess.run("kdestroy", check=True, shell=True)


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_realm_match_case_sensitive_positive(bouncer):
    """
    Test that realm match functions when used in bouncer wide config
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer.auth_path}
        admin_users = pgbouncer
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
        auth_gss_parameter = krb_realm={REALM}
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_realm_match_case_insensitive_negative(bouncer):
    """
    Test that realm match works in bouncer wide config when used with case
    insensitive mode.
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        admin_users = pgbouncer
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
        auth_krb_caseins_users = 1
        auth_gss_parameter = krb_realm={REALM.swapcase()}a
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="GSS authentication failed"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_realm_match_case_insensitive_positive(bouncer):
    """
    Test that realm match mode correctly accepts match even with differences
    in case.
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_hba_file = pgbouncer_hba.conf
        auth_file = userlist.txt
        auth_krb_caseins_users = 1
        auth_gss_parameter = krb_realm={REALM.swapcase()}
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_hba_case_insensitive_positive_realm_match(bouncer):
    """
    Test that user is accepted even with case sensativity issues when using HBA
    realm checking.
    """
    hba_conf_file = bouncer.config_dir / "hba.conf"
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = hba
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_krb_caseins_users = 1
        auth_hba_file = {hba_conf_file}
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
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
    with bouncer.run_with_config(config):
        bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_hba_case_sensitive_negative_realm_match(bouncer):
    """
    Test that user is rejected when using case insesitive realm match with HBA
    """
    hba_conf_file = bouncer.config_dir / "hba.conf"

    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = hba
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        logfile = {bouncer.log_path}
        admin_users = pgbouncer
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
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

    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        with pytest.raises(psycopg.OperationalError, match="GSS authentication failed"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_accept_delegation(bouncer):
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_gss_accept_delegation = 1
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=KADMIN_PRINCIPAL_FULL, dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_bouncer_config_include_realm_disabled(bouncer):
    """
    Test include realm functionality for bouncer wide gss config
    """
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = gss
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_gss_parameter = include_realm=0
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with bouncer.run_with_config(config):
        bouncer.test(user=getpass.getuser(), dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=getpass.getuser(), dbname="postgres")


@pytest.mark.skipif(not GSS_SUPPORT, reason="pgbouncer is built without GSS support")
def test_hba_include_realm_disabled(bouncer):
    """
    Test include realm functionality for HBA config
    """
    hba_conf_file = bouncer.config_dir / "hba.conf"
    config = f"""
        [databases]
        postgres = host={bouncer.pg.host} port={bouncer.pg.port} user=postgres

        [pgbouncer]
        listen_addr = 127.0.0.1
        auth_type = hba
        auth_file = {bouncer.auth_path}
        listen_port = {bouncer.port}
        admin_users = pgbouncer
        logfile = {bouncer.log_path}
        auth_krb_server_keyfile = {KEYTAB_FILEPATH}
        auth_hba_file = {hba_conf_file}
    """
    subprocess.run(f"echo {KADMIN_PASSWORD} | kinit", check=True, shell=True)
    with open(hba_conf_file, "w") as f:
        hba_entry = [
            "host",
            "postgres",
            getpass.getuser(),
            "0.0.0.0/0",
            "gss",
            "include_realm=0",
        ]
        f.write(" ".join(hba_entry))
    with bouncer.run_with_config(config):
        bouncer.test(user=getpass.getuser(), dbname="postgres")
        subprocess.run("kdestroy", check=True, shell=True)
        with pytest.raises(psycopg.OperationalError, match="GSSAPI continuation error"):
            bouncer.test(user=getpass.getuser(), dbname="postgres")
