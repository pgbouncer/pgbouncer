#! /bin/sh

# get install-sh, config.*
rm -f config.sub config.guess install-sh ltmain.sh
libtoolize --install --copy
rm -f ltmain.sh

rm -f lib/usual/config.* configure
autoreconf -I lib/m4 -f
rm -rf autom4te*

