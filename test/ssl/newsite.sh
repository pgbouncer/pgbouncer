#! /bin/sh

# new server key + cert under some CA

test -n "$2" || {
  echo "usage: $0 <CaName> <SiteDns>"
  exit 1
}

test -f "$1/ca.key" || {
  echo "CA $1 does not exist"
  exit 1
}

days=1024

. ./lib.sh

CaName="$1"
DstName="$2"
shift 2

ser=`cat $CaName/serial`

pfx=$CaName/sites/${ser}-$DstName

run openssl ecparam -genkey -name prime256v1 -out $pfx.key

# cert reqs
run_req -new -key "$pfx.key" -out "$pfx.csr" -- CN="$DstName" "$@"

# accept certs
run_ca -days $days -policy pol-server -in "$pfx.csr" -out "$pfx.crt"
