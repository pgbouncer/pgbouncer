#!/bin/bash

set -euo pipefail

# When V is 1, print commands and build progress.
export V=1

NAME="cf-pgbouncer"
VERSION=$(git describe --tags --always --dirty="-dev")

mkdir -p ./root/usr/bin

fpm -t deb \
  --deb-user root \
  --deb-group root \
  --url https://bitbucket.cfdata.org/projects/DB/repos/pgbouncer \
  --vendor Cloudflare \
  --maintainer "Database Team" \
  --description "Cloudflare PgBouncer Fork" \
  -s dir \
  -n "$NAME" \
  -v "$VERSION" \
  -C ./root \
  --package ./artifacts/ \
  .

rm -rf ./root
