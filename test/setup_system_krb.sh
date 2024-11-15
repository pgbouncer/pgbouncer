#!/usr/bin/env bash
set -eoux

REALM="EXAMPLE.COM"
SUPPORTED_ENCRYPTION_TYPES="aes256-cts-hmac-sha1-96:normal"
KADMIN_PRINCIPAL="root"
KADMIN_PASSWORD="root"
# TODO Replace with bash
KDC_KADMIN_SERVER=$(cat /etc/hostname)
LOGDIR="log"
PG_LOG="${LOGDIR}/krb.log"
# Assumes packages are installed; krb5-kdc and krb5-admin-server on debian
KADMIN_PRINCIPAL_FULL="${KADMIN_PRINCIPAL}@${REALM}"
MASTER_PASSWORD="master_password"


echo "
[libdefaults]
        default_realm = ${REALM}
        rdns = false

[realms]
        ${REALM} = {
                kdc_ports = 88,750
                kadmind_port = 749
                kdc = ${KDC_KADMIN_SERVER}
                admin_server = ${KDC_KADMIN_SERVER}
        }
" > /etc/krb5.conf

echo "
[realms]
        ${REALM} = {
                acl_file = /etc/krb5kdc/kadm5.acl
                max_renewable_life = 7d 0h 0m 0s
                supported_enctypes = ${SUPPORTED_ENCRYPTION_TYPES}
                default_principal_flags = +preauth
        }
" > /etc/krb5kdc/kdc.conf


echo "${KADMIN_PRINCIPAL_FULL} *" > /etc/krb5kdc/kadm5.acl
