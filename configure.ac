dnl Process this file with autoconf to produce a configure script.

AC_INIT(pgbouncer, 1.0.2)
AC_CONFIG_SRCDIR(src/bouncer.h)
AC_CONFIG_HEADER(config.h)

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP

dnl Additional gcc tuning
if test x"$GCC" = xyes; then
  AC_MSG_CHECKING([for working warning swithces])
  good_CFLAGS="$CFLAGS"
  good="-Wall"
  flags="-Wextra"
  # turn off noise from Wextra
  flags="$flags -Wno-unused-parameter -Wno-sign-compare"
  flags="$flags -Wno-missing-field-initializers"
  # Wextra does not turn those on?
  flags="$flags -Wmissing-prototypes -Wpointer-arith -Wendif-labels"
  flags="$flags -Wdeclaration-after-statement -Wold-style-definition"
  flags="$flags -Wstrict-prototypes"
  for f in $flags; do
    CFLAGS="$good_CFLAGS $good $f"
    AC_COMPILE_IFELSE([void foo(void){}], [good="$good $f"])
  done
  CFLAGS="$good_CFLAGS $good"
  AC_MSG_RESULT([$good])
fi

dnl Checks for header files.
AC_CHECK_HEADERS([crypt.h sys/socket.h sys/ucred.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_SYS_LARGEFILE

dnl Checks for library functions.
AC_CHECK_FUNCS(strlcpy strlcat)
AC_SEARCH_LIBS(crypt, crypt, [], AC_MSG_ERROR([crypt not found]))

dnl Find libevent
AC_MSG_CHECKING([for libevent])
AC_ARG_WITH(libevent,
  AC_HELP_STRING([--with-libevent=prefix],[Specify where libevent is installed]),
  [ test "$withval" = "no" && AC_MSG_ERROR("cannot work without libevent")
    CPPFLAGS="$CPPFLAGS -I$withval/include"
    LDFLAGS="$LDFLAGS -L$withval/lib" ])
LIBS="$LIBS -levent"
AC_LINK_IFELSE([
  #include <sys/types.h>
  #include <sys/time.h>
  #include <stdio.h>
  #include <event.h>
  int main(void) {
    struct event ev;
    event_init();
    event_set(&ev, 1, EV_READ, NULL, NULL);
  } ],
[AC_MSG_RESULT([found])],
[AC_MSG_ERROR([not found])])

# autoconf does not want to find 'install', if not using automake...
INSTALL=install

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],[build binary with debugging symbols]))
AC_MSG_CHECKING([whether to build debug binary])
if test "$enable_debug" = "yes"; then
  LDFLAGS="-g $LDFLAGS"
  CFLAGS="`echo $CFLAGS | sed -e 's/-O2/-O/g'`"
  BININSTALL="$INSTALL"
  AC_MSG_RESULT([yes])
else
  if test x"$GCC" = xyes; then
    CFLAGS="$CFLAGS -fomit-frame-pointer"
  fi
  BININSTALL="$INSTALL -s"
  AC_MSG_RESULT([no])
fi
AC_SUBST(enable_debug)
AC_SUBST(INSTALL)
AC_SUBST(BININSTALL)

AC_ARG_ENABLE(cassert, AC_HELP_STRING([--enable-cassert],[turn on assert checking in code]))
AC_MSG_CHECKING([whether to enable asserts])
if test "$enable_cassert" = "yes"; then
  AC_DEFINE(CASSERT, 1, [Define to enable assert checking])
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

AC_ARG_ENABLE(werror, AC_HELP_STRING([--enable-werror],[add -Werror to CFLAGS]))
AC_MSG_CHECKING([whether to fail on warnings])
if test "$enable_werror" = "yes"; then
  CFLAGS="$CFLAGS -Werror"
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

dnl Output findings
AC_OUTPUT([config.mak])

dnl If separate build dir, link Makefile over
test -f Makefile || {
  echo "Linking Makefile"
  ln -s $srcdir/Makefile
}

