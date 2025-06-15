#! /bin/sh

# autogen for non-automake trees
#
# - it installs files: config.sub, config.guess, install-sh
# - it installs ltmain.sh, if LT_INIT or *LIBTOOL macro is used
#

set -e

USUAL_DIR="$1"
test -n "${USUAL_DIR}" || USUAL_DIR="."

test -f "${USUAL_DIR}/m4/usual.m4" || {
  echo usage: $0 USUAL_DIR
  exit 1
}

# default programs
ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOHEADER=${AUTOHEADER:-autoheader}

# If neither ACLOCAL/AUTOCONF/AUTOHEADER and
# AUTOCONF_VERSION/AUTOMAKE_VERSION are configured,
# pick any modern version to avoid pointless errors.

if test "$AUTOCONF_VERSION" = ""; then
  if test "$AUTOCONF" = "autoconf"; then
    for ac in 75 74 73 72 71 70 69 68 67 66 65 64 63 62 61 60 59; do
      ac="2.$ac"
      if which autoconf-$ac > /dev/null 2>&1; then
        AUTOCONF_VERSION="$ac"
        echo "Using autoconf: $AUTOCONF_VERSION"
        break
      fi
      if which autoconf$ac > /dev/null 2>&1; then
        AUTOCONF_VERSION="$ac"
        echo "Using autoconf: $AUTOCONF_VERSION"
        break
      fi
    done
  fi
fi

if test "$AUTOMAKE_VERSION" = ""; then
  if test "$ACLOCAL" = "aclocal"; then
    for am in 1.19 1.18 1.17 1.16 1.15 1.14 1.13 1.12 1.11 1.10 1.9; do
      if which aclocal-$am > /dev/null 2>&1; then
        AUTOMAKE_VERSION="$am"
        echo "Using aclocal: $AUTOMAKE_VERSION"
        break
      fi
      if which aclocal$am > /dev/null 2>&1; then
        AUTOMAKE_VERSION="$am"
        echo "Using aclocal: $AUTOMAKE_VERSION"
        break
      fi
    done
  fi
fi

export AUTOCONF_VERSION AUTOMAKE_VERSION

# detect first glibtoolize then libtoolize
if test "x$LIBTOOLIZE" = "x"; then
  LIBTOOLIZE=glibtoolize
  which $LIBTOOLIZE >/dev/null 2>&1 \
    || LIBTOOLIZE=libtoolize
fi

#
# Workarounds for libtoolize randomness - it does not update
# the files if they exist, except it requires install-sh.
#
rm -f config.guess config.sub install-sh ltmain.sh libtool
cp -p ${USUAL_DIR}/mk/install-sh .
if ${LIBTOOLIZE} --help | grep "[-][-]install" > /dev/null; then
  ${LIBTOOLIZE} -i -f -q -c
else
  ${LIBTOOLIZE} -c
fi

# drop ltmain.sh if libtool is not used
grep -E 'LT_INIT|LIBTOOL' configure.ac > /dev/null \
  || rm -f ltmain.sh

# Now generate configure & config.h
${ACLOCAL} -I ${USUAL_DIR}/m4

grep AC_CONFIG_HEADER configure.ac > /dev/null \
  && ${AUTOHEADER}

${AUTOCONF}

# clean junk
rm -rf autom4te.* aclocal*
