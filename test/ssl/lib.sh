#! /bin/sh

# PEM format

# req fields
# C  = Country
# ST = State/Province
# L = Locality
# O = Organization
# OU = Org Unit
# CN = commonName
# ? = emailAddress

umask 077

run() {
  echo '$' "$@"
  "$@" 2>&1 | sed 's/^/  > /'
}

# key -> csr
run_req() {
  tmp="csr.template"
  args=""
  while test "$1" != '--'; do
    args="$args $1"
    shift
  done
  shift

  (
    echo "[req]"
    echo "prompt=no"
    echo "distinguished_name=req_distinguished_name"
    echo "[req_distinguished_name]"
    for arg; do echo "$arg"; done
  ) > "$tmp"
  run openssl req $args -config "$tmp"
  rm -f csr.template
}

run_ca() {
  ser=`cat ${CaName}/serial`
  run openssl ca -batch -config "${CaName}/config.ini" "$@"
  while test "$1" != '-out'; do
    shift
  done
  if test "$1" = '-out'; then
    cp "${CaName}/certs/$ser.pem" "$2" 2>/dev/null
  fi
}
