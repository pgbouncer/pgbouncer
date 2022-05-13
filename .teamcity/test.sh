#!/bin/bash

set -euo pipefail

# When V is 1, print commands and build progress.
export V=1

git submodule init
git submodule update

./autogen.sh
LIBS=-lpthread ./configure --prefix=/usr/local --enable-evdns=no --with-openssl=/opt/boringssl-fips

get_pg_version() {
  debian_version=$(grep -o '^[0-9]*' /etc/debian_version)
  # stretch has Postgres 9.6 installed
  if [[ $debian_version == 9 ]]; then
    echo "9.6"
  # buster has Postgres 11 installed
  elif [[ $debian_version == 10 ]]; then
    echo "11"
  # bullseye has Postgres 13 installed
  elif [[ $debian_version == 11 ]]; then
    echo "13"
  else
    echo "Debian build version $DEBIAN_BUILD_VERSION not supported"
    exit 1
  fi
}

export PATH="$PATH:/usr/lib/postgresql/$(get_pg_version)/bin"
make check
