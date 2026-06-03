#!/bin/sh
set -e

for file in '/usr/sbin/slapd' '/usr/local/libexec/slapd' '/opt/homebrew/opt/openldap/libexec/slapd' '/usr/local/opt/openldap/libexec/slapd' '/opt/local/libexec/slapd'; do
	if [ -e "$file" ]; then
		slapd=$file
	fi
done
if [ -z "$slapd" ]; then
	exit 77
fi

for dir in '/etc/ldap/schema' '/etc/openldap/schema' '/usr/local/etc/openldap/schema' '/opt/homebrew/etc/openldap/schema' '/opt/local/etc/openldap/schema'; do
	if [ -d "$dir" ]; then
		ldap_schema_dir=$dir
	fi
done
if [ -z "$ldap_schema_dir" ]; then
	exit 77
fi


ldap_dir=$1/ldap
mkdir -p ${ldap_dir}
ldap_datadir="${ldap_dir}/openldap-data"
slapd_conf="${ldap_dir}/slapd.conf"
slapd_pidfile="${ldap_dir}/slapd.pid"
slapd_logfile="${ldap_dir}/slapd.log"
ldap_conf="${ldap_dir}/ldap.conf"
slapd_certs="${ldap_dir}/slapd-certs"

ldap_server='localhost'
ldap_port=$2
ldaps_port=$3
ldap_url="ldap://$ldap_server:$ldap_port"
ldaps_url="ldaps://$ldap_server:$ldaps_port"
ldap_basedn='dc=example,dc=net'
ldap_rootdn='cn=Manager,dc=example,dc=net'
ldap_rootpw='secret'

cat >$slapd_conf <<-EOF
include $ldap_schema_dir/core.schema
include $ldap_schema_dir/cosine.schema
include $ldap_schema_dir/nis.schema
include $ldap_schema_dir/inetorgperson.schema
pidfile $slapd_pidfile
logfile $slapd_logfile
access to *
        by * read
        by anonymous auth

database ldif
directory $ldap_datadir

TLSCACertificateFile $slapd_certs/ca.crt
TLSCertificateFile $slapd_certs/server.crt
TLSCertificateKeyFile $slapd_certs/server.key

suffix "dc=example,dc=net"
rootdn "$ldap_rootdn"
rootpw $ldap_rootpw
EOF


cat >$ldap_conf <<-EOF
TLS_REQCERT never
EOF

if [ -d $ldap_datadir ];then
	rm -rf $ldap_datadir
fi
mkdir -p $ldap_datadir
mkdir -p ${slapd_certs}

openssl req -new -nodes -keyout "$slapd_certs/ca.key" -x509 -out "$slapd_certs/ca.crt" -subj "/CN=CA"
openssl req -new -nodes -keyout "$slapd_certs/server.key" -out "$slapd_certs/server.csr" -subj "/CN=server"
openssl x509 -req -in "$slapd_certs/server.csr" -CA "$slapd_certs/ca.crt" -CAkey "$slapd_certs/ca.key" "-CAcreateserial" -out "$slapd_certs/server.crt"


cat > $ldap_dir/ldap.ldif <<-EOF
dn: dc=example,dc=net
objectClass: top
objectClass: dcObject
objectClass: organization
dc: example
o: ExampleCo

dn: uid=ldapuser1,dc=example,dc=net
objectClass: inetOrgPerson
objectClass: posixAccount
uid: ldapuser1
sn: Lastname
givenName: Firstname
cn: First Test User
displayName: First Test User
uidNumber: 101
gidNumber: 100
homeDirectory: /home/ldapuser1
mail: ldapuser1@example.net

EOF


export LDAPURI=$ldaps_url
export LDAPBINDDN=$ldap_rootdn
export LDAPCONF=$ldap_conf

echo $slapd "-f" $slapd_conf "-h" "$ldap_url $ldaps_url"
$slapd -f $slapd_conf -h "$ldap_url $ldaps_url" && sleep 1

echo ldapadd -x -w $ldap_rootpw -f $ldap_dir/ldap.ldif -H $ldap_url
ldapadd -x -w $ldap_rootpw -f $ldap_dir/ldap.ldif
ldappasswd -x -w $ldap_rootpw -s secret1 'uid=ldapuser1,dc=example,dc=net'
ldapsearch -x -b "dc=example,dc=net"
