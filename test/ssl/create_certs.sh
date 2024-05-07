#! /bin/sh

set -e

rm -rf TestCA1 TestCA2
./newca.sh TestCA1 C=QQ O=Org1 CN="TestCA1"
./newsite.sh TestCA1 localhost C=QQ O=Org1 L=computer OU=db
./newsite.sh TestCA1 bouncer C=QQ O=Org1 L=computer OU=Dev
./newsite.sh TestCA1 random C=QQ O=Org1 L=computer OU=Dev
./newsite.sh TestCA1 pgbouncer.acme.org C=QQ O=Org1 L=computer OU=Dev
./newca.sh TestCA2 C=QQ O=Org2 CN="TestCA2"
./newsite.sh TestCA2 localhost C=QQ O=Org1 L=computer OU=db
