#! /bin/sh

# get install-sh, config.*
rm -f config.sub config.guess install-sh ltmain.sh

if libtoolize --help | grep "[-][-]install" > /dev/null; then
  libtoolize --install --copy
else
  libtoolize --copy
fi

rm -f ltmain.sh

rm -f lib/usual/config.* configure

aclocal -I ./lib/m4
autoheader
autoconf

rm -rf autom4te*

