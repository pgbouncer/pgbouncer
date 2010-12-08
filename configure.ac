dnl Process this file with autoconf to produce a configure script.

AC_INIT(pgbouncer, 1.4)
AC_CONFIG_SRCDIR(src/janitor.c)
AC_CONFIG_HEADER(lib/usual/config.h)
AC_PREREQ([2.59])

dnl unix/win32
AC_USUAL_PORT_CHECK

dnl Checks for programs.
AC_USUAL_PROGRAM_CHECK

dnl asciidoc >= 8.2
AC_CHECK_PROGS(ASCIIDOC, asciidoc)
if test -n "$ASCIIDOC"; then
  AC_MSG_CHECKING([for asciidoc version >= 8.2])
  ver=`$ASCIIDOC --version 2>&1 | sed -e 's/asciidoc //'`
  case "$ver" in
dnl hack to make possible to use [, ] in regex
changequote({, })dnl
  [0-7].*|8.[01]|8.[01].*)
changequote([, ])dnl
      AC_MSG_RESULT([$ver, too old])
      ASCIIDOC=""
      ;;
  *)
      AC_MSG_RESULT([$ver, ok])
      ;;
  esac
fi

dnl check for xmlto, but only if asciidoc is found
if test -n "$ASCIIDOC"; then
  AC_CHECK_PROGS(XMLTO, xmlto)
fi

dnl check for windows tools
if test "$PORTNAME" = "win32"; then
  AC_CHECK_TOOL([WINDRES], [windres])
  AC_CHECK_TOOL([DLLWRAP], [dllwrap])
  AC_CHECK_TOOL([DLLTOOL], [dlltool])
fi
AC_CHECK_TOOL([STRIP], [strip])

dnl Checks for header files.
AC_USUAL_HEADER_CHECK
AC_CHECK_HEADERS([crypt.h])
AC_CHECK_HEADERS([sys/resource.h sys/wait.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_USUAL_TYPE_CHECK

dnl autoconf 2.59 does not have UINT macros nor docdir
m4_ifdef([AC_TYPE_UINT8_T], [
  AC_TYPE_UINT8_T
  AC_TYPE_UINT32_T
  AC_TYPE_UINT64_T
], [
  datarootdir='${prefix}/share'
  docdir='${datarootdir}/doc/${PACKAGE_TARNAME}'
  AC_SUBST(datarootdir)
  AC_SUBST(docdir)
])

dnl Checks for library functions.
AC_USUAL_FUNCTION_CHECK
AC_SEARCH_LIBS(crypt, crypt)
AC_SEARCH_LIBS(clock_gettime, rt)
AC_SEARCH_LIBS(getsockname, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(hstrerror, resolv)
AC_CHECK_FUNCS(crypt lstat)

dnl Find libevent
AC_USUAL_LIBEVENT

use_evdns=no
AC_ARG_ENABLE(evdns, AC_HELP_STRING([--enable-evdns],[Use libevent for DNS lookups]),
              [use_evdns=yes])
AC_MSG_CHECKING([whether to use libevent for DNS lookups])
if test "$use_evdns" = "yes"; then
  AC_DEFINE(USE_EVDNS, 1, [Use libevent for DNS lookups.])
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

AC_USUAL_DEBUG
AC_USUAL_CASSERT
AC_USUAL_WERROR

if test \! "$srcdir" = "$builddir"; then
  CPPFLAGS="-I\$(builddir)/include $CPPFLAGS"
fi

dnl Output findings
AC_OUTPUT([config.mak])

dnl If separate build dir, link Makefile over
test -f Makefile || {
  echo "Linking Makefile"
  ln -s $srcdir/Makefile
}

