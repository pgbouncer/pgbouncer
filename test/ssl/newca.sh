#! /bin/sh

# create new CA

set -e

test -n "$1" || {
  echo "usage: $0 CaName [K=V]*"
  exit 1
}

test -d "$1" && {
  echo "CA '$1' already exists"
  exit 1
}

name="$1"
shift

mkdir -p "$name"/certs
mkdir -p "$name"/sites
touch "$name"/index.txt
echo 01 > "$name"/serial

. ./lib.sh

days=10240

#run openssl genrsa -out "$name/ca.key" $ksize
run openssl ecparam -name prime256v1 -genkey -out "$name/ca.key"

# self-signed cert
# the -addext option is not required for old OpenSSL versions
openssl_version=`openssl version | awk '{print $2}'`
if expr "X$openssl_version" : 'X1.*.*' >/dev/null; then
  run_req -new -x509 -days $days -key "$name/ca.key" -out "$name/ca.crt" -- "$@"
else
  run_req -new -x509 -days $days -key "$name/ca.key" -out "$name/ca.crt" -addext basicConstraints=critical,CA:TRUE,pathlen:1 -- "$@"
fi


cat > "$name"/config.ini <<EOF
[ca]
default_ca = test-ca

[test-ca]
dir            = $name                # top dir
database       = \$dir/index.txt      # index file.
new_certs_dir  = \$dir/certs          # new certs dir
certificate    = \$dir/ca.crt         # The CA cert
serial         = \$dir/serial         # serial no file
private_key    = \$dir/ca.key         # CA private key

default_md = sha256

policy = pol-user

[pol-user]
C = supplied
L = supplied
#ST = supplied
O = supplied
OU = supplied
CN = supplied
emailAddress = supplied

[pol-server]
C = supplied
L = supplied
#ST = supplied
O = supplied
OU = supplied
CN = supplied

EOF
