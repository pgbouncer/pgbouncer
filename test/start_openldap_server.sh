#!/bin/bash
set -e

slapd=/usr/sbin/slapd
if [ -d '/etc/ldap/schema' ]
then
	ldap_schema_dir='/etc/ldap/schema'
else
	ldap_schema_dir='/etc/openldap/schema'
fi
if [ ! -e $slapd ];then
	return 77
fi


ldap_dir=$1/ldap
mkdir -p ${ldap_dir}
ldap_datadir="${ldap_dir}/openldap-data"
slapd_conf="${ldap_dir}/slapd.conf"
slapd_pidfile="${ldap_dir}/slapd.pid"
slapd_logfile="${ldap_dir}/slapd.log"
ldap_conf="${ldap_dir}/ldap.conf"

ldap_server='localhost'
ldap_port=$2
ldap_url="ldap://$ldap_server:$ldap_port"
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

echo $slapd "-f" $slapd_conf "-h" $ldap_url
$slapd -f $slapd_conf -h $ldap_url && sleep 1
export LDAPURI=$ldap_url
export LDAPBINDDN=$ldap_rootdn
export LDAPCONF=$ldap_conf

echo ldapadd -x -w $ldap_rootpw -f $ldap_dir/ldap.ldif -H $ldap_url
ldapadd -x -w $ldap_rootpw -f $ldap_dir/ldap.ldif
ldappasswd -x -w $ldap_rootpw -s secret1 'uid=ldapuser1,dc=example,dc=net'
ldapsearch -x -b "dc=example,dc=net"
