#!/bin/bash

set -euo pipefail

# When V is 1, print commands and build progress.
export V=1

NAME="cf-pgbouncer"
VERSION=$(git describe --tags --always --dirty="-dev")

# Put compiled binary in target folder that will be packaged up.
mkdir -p ./root/usr/bin
cp ./pgbouncer ./root/usr/bin

# This folder will contain the packaged .deb file
mkdir artifacts

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
  --package ./artifacts/pgbouncer.deb \
  .

rm -rf ./root