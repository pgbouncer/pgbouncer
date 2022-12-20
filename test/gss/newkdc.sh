#! /bin/sh

# TODO: do not run if /etc/krb5.conf exists, kdc or kadmin is running, or if /var/lib/krb5kdc exists

# TODO: remove after debugging
apt-get update
env DEBIAN_FRONTEND=noninteractive apt-get -y install curl gnupg lsb-release krb5-kdc krb5-admin-server krb5-user

cd $(dirname $0)

REALM=EXAMPLE.COM
SUPPORTED_ENCRYPTION_TYPES=aes256-cts-hmac-sha1-96:normal
KADMIN_PRINCIPAL=kadmin/admin
KADMIN_PASSWORD=51rb0unc3r
KDC_KADMIN_SERVER=$(hostname -f)

LOGDIR=log
PG_LOG=$LOGDIR/krb.log

ulimit -c unlimited

configure_kdc() {
	# Assumes packages are installed; krb5-kdc and krb5-admin-server on debian
	command -v krb5kdc > /dev/null || {
	        echo "krb5kdc not found, need kerberos tools in PATH"
        	exit 0
	}
	KADMIN_PRINCIPAL_FULL=$KADMIN_PRINCIPAL@$REALM
	cat << EOF > /etc/krb5.conf
[libdefaults]
        default_realm = $REALM
        rdns = false

[realms]
        $REALM = {
                kdc_ports = 88,750
                kadmind_port = 749
                kdc = $KDC_KADMIN_SERVER
                admin_server = $KDC_KADMIN_SERVER
        }
EOF

	cat << EOF > /etc/krb5kdc/kdc.conf
[realms]
        $REALM = {
                acl_file = /etc/krb5kdc/kadm5.acl
                max_renewable_life = 7d 0h 0m 0s
                supported_enctypes = $SUPPORTED_ENCRYPTION_TYPES
                default_principal_flags = +preauth
        }
EOF
	cat << EOF > /etc/krb5kdc/kadm5.acl
$KADMIN_PRINCIPAL_FULL *
EOF
	MASTER_PASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1)
	# This command also starts the krb5-kdc and krb5-admin-server services
	krb5_newrealm <<EOF
$MASTER_PASSWORD
$MASTER_PASSWORD
EOF
	kadmin.local -q "delete_principal -force $KADMIN_PRINCIPAL_FULL"
	kadmin.local -q "addprinc -pw $KADMIN_PASSWORD $KADMIN_PRINCIPAL_FULL"
}

add_users () {
	export KDC_KADMIN_SERVER=$(hostname -f)
	rm -f /krb5.keytab
	rm -f /bouncer.keytab
	kadmin.local -q "delete_principal -force postgres"
	kadmin.local -q "delete_principal -force postgres/${KDC_KADMIN_SERVER}"
	kadmin.local -q "delete_principal -force bouncer"
	kadmin.local -q "delete_principal -force bouncer/${KDC_KADMIN_SERVER}"

	kadmin.local -q "addprinc -randkey postgres"
	kadmin.local -q "addprinc -randkey postgres/${KDC_KADMIN_SERVER}"
	kadmin.local -q "ktadd -k /krb5.keytab postgres/${KDC_KADMIN_SERVER}"
	kadmin.local -q "ktadd -k /krb5.keytab postgres"
	chmod 644 /krb5.keytab

	kadmin.local -q "addprinc -randkey bouncer"
	kadmin.local -q "addprinc -randkey bouncer/${KDC_KADMIN_SERVER}"
	kadmin.local -q "ktadd -k /bouncer.keytab bouncer/${KDC_KADMIN_SERVER}"
	kadmin.local -q "ktadd -k /bouncer.keytab bouncer"
	chmod 644 /bouncer.keytab
}

configure_kdc
add_users
