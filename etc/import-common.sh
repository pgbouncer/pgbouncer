#! /bin/sh

set -eu

# Script to import common files from PostgreSQL source tree for SCRAM
# support.  Run this from time to time, ideally against the latest
# tagged and released stable minor version of PostgreSQL.
#
# The files are not taken verbatim.  Especially the header file
# includes are adjusted.  So go through the changes with "git app -p"
# or similar after this.

pgsrcdir=$1

common_include='
src/include/common/base64.h
src/include/mb/pg_wchar.h
src/include/common/saslprep.h
src/include/common/scram-common.h
src/include/common/unicode_norm.h
src/include/common/unicode_norm_table.h
'

common_src='
src/common/base64.c
src/common/saslprep.c
src/common/scram-common.c
src/common/unicode_norm.c
src/backend/utils/mb/wchar.c
'

for file in $common_include; do cp -v $pgsrcdir/$file include/common/; done
for file in $common_src; do cp -v $pgsrcdir/$file src/common; done
