#! /bin/sh

createdb conntest

./pgbouncer -d ctest6000.ini
./pgbouncer -d ctest7000.ini

./asynctest

# now run conntest.sh on another console
