#!/bin/bash
#
# Set up a local MIT KDC for pgbouncer GSSAPI integration tests.
#
# This script is designed to run inside a disposable container or CI
# environment.  It overwrites /etc/krb5.conf and /etc/krb5kdc/ config.
# Do NOT run on a production host.
#
# After this script completes:
#   - KDC config and database are created and the krb5kdc daemon is left running,
#     ready for the tests to kinit against
#   - User principal: testuser@TEST.PGBOUNCER (password: testpass)
#   - Service principal: postgres/localhost@TEST.PGBOUNCER
#   - Keytab: /tmp/pgbouncer-test.keytab (world-readable for test use)
#   - auth_to_local rules strip the realm via gss_localname()
#

set -euo pipefail

REALM="TEST.PGBOUNCER"
KDC_DIR="/etc/krb5kdc"
KEYTAB="/tmp/pgbouncer-test.keytab"
MASTER_PASSWORD="masterpass"
USER_PRINCIPAL="testuser@${REALM}"
USER_PASSWORD="testpass"
SVC_PRINCIPAL_LOCALHOST="postgres/localhost@${REALM}"
SVC_PRINCIPAL_IP="postgres/127.0.0.1@${REALM}"

# --- krb5.conf ---
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true

[realms]
    ${REALM} = {
        kdc = localhost
        admin_server = localhost
        auth_to_local = RULE:[1:\$1@\$0](.*@${REALM})s/@.*//
        auth_to_local = DEFAULT
    }

[domain_realm]
    localhost = ${REALM}
    .localhost = ${REALM}
EOF

# --- kdc.conf ---
mkdir -p "${KDC_DIR}"
cat > "${KDC_DIR}/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    ${REALM} = {
        database_name = ${KDC_DIR}/principal
        admin_keytab = FILE:${KDC_DIR}/kadm5.keytab
        acl_file = ${KDC_DIR}/kadm5.acl
        key_stash_file = ${KDC_DIR}/stash
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        max_life = 24h
        max_renewable_life = 7d
    }
EOF

# --- kadm5.acl ---
cat > "${KDC_DIR}/kadm5.acl" <<EOF
*/admin@${REALM} *
EOF

# --- Create KDC database ---
# In containers, /dev/random may block waiting for entropy.
# Start haveged if available to feed the kernel entropy pool.
if command -v haveged >/dev/null 2>&1; then
    haveged -F &
    HAVEGED_PID=$!
    sleep 1
fi
kdb5_util create -s -r "${REALM}" -P "${MASTER_PASSWORD}" 2>/dev/null || true
if [ -n "${HAVEGED_PID:-}" ]; then
    kill "${HAVEGED_PID}" 2>/dev/null || true
fi

# --- Start the KDC (left running for the tests to authenticate against) ---
krb5kdc
sleep 1

# --- Create principals ---
kadmin.local -q "delete_principal -force ${USER_PRINCIPAL}" 2>/dev/null || true
kadmin.local -q "delete_principal -force ${SVC_PRINCIPAL_LOCALHOST}" 2>/dev/null || true
kadmin.local -q "delete_principal -force ${SVC_PRINCIPAL_IP}" 2>/dev/null || true

kadmin.local -q "addprinc -pw ${USER_PASSWORD} ${USER_PRINCIPAL}"
kadmin.local -q "addprinc -randkey ${SVC_PRINCIPAL_LOCALHOST}"
kadmin.local -q "addprinc -randkey ${SVC_PRINCIPAL_IP}"

# --- Extract keytab (both localhost and 127.0.0.1 SPNs for test flexibility) ---
rm -f "${KEYTAB}"
kadmin.local -q "ktadd -k ${KEYTAB} ${SVC_PRINCIPAL_LOCALHOST}"
kadmin.local -q "ktadd -k ${KEYTAB} ${SVC_PRINCIPAL_IP}"
chmod 644 "${KEYTAB}"

echo ""
echo "KDC setup complete:"
echo "  Realm:     ${REALM}"
echo "  User:      ${USER_PRINCIPAL} (password: ${USER_PASSWORD})"
echo "  Service:   ${SVC_PRINCIPAL_LOCALHOST}, ${SVC_PRINCIPAL_IP}"
echo "  Keytab:    ${KEYTAB}"
echo ""
klist -k -t "${KEYTAB}"
