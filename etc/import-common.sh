#! /bin/sh

set -eu

# Script to import common files from PostgreSQL source tree for SCRAM
# support.  Run this from time to time, ideally against the latest
# tagged and released stable minor version of PostgreSQL.
#
# The files are not taken verbatim.  Especially the header file
# includes are adjusted.  So go through the changes with "git add -p"
# or similar after this.

pgsrcdir=$1

common_include='
src/common/md5_int.h
src/common/sha1_int.h
src/common/sha2_int.h
src/include/common/base64.h
src/include/common/md5.h
src/include/common/sha1.h
src/include/common/sha2.h
src/include/common/saslprep.h
src/include/common/scram-common.h
src/include/common/unicode_combining_table.h
src/include/common/unicode_east_asian_fw_table.h
src/include/common/unicode_norm.h
src/include/common/unicode_norm_table.h
src/include/common/cryptohash.h
src/include/common/hmac.h
src/include/mb/pg_wchar.h
'

common_src='
src/common/base64.c
src/common/cryptohash.c
src/common/hmac.c
src/common/md5.c
src/common/sha1.c
src/common/sha2.c
src/common/saslprep.c
src/common/scram-common.c
src/common/unicode_norm.c
src/common/wchar.c
'

for file in $common_include; do cp -v $pgsrcdir/$file include/common/; done
for file in $common_src; do cp -v $pgsrcdir/$file src/common; done
