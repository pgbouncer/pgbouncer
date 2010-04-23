dnl Process this file with autoconf to produce a configure script.

AC_INIT(pgbouncer, 1.3.3rc1)
AC_CONFIG_SRCDIR(src/janitor.c)
AC_CONFIG_HEADER(include/config.h)
AC_PREREQ([2.59])

dnl windows port check (Not use AC_CANONICAL_HOST)
AC_MSG_CHECKING([target host type])
xhost="$host_alias"
if test "x$xhost" = "x"; then
  xhost=`uname -s`
fi
case $xhost in
*cygwin* | *mingw* | *pw32* | *MINGW*)
   LIBS="$LIBS -lws2_32"
   PORTNAME=win32;;
*) PORTNAME=unix ;;
esac
AC_SUBST(PORTNAME)
AC_MSG_RESULT([$PORTNAME])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP

dnl Check if linker supports -Wl,--as-needed
dnl That helps to get rid of unnecessary -lrt
if test "$GCC" = "yes"; then
  old_LDFLAGS="$LDFLAGS"
  LDFLAGS="$LDFLAGS -Wl,--as-needed"
  AC_MSG_CHECKING([whether linker supports --as-needed])
  AC_LINK_IFELSE([int main(void) { return 0; }],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])
     LDFLAGS="$old_LDFLAGS"])
fi

dnl Check if compiler supports __func__
AC_CACHE_CHECK([whether compiler supports __func__], pgac_cv_funcname_func,
  [AC_TRY_COMPILE([#include <stdio.h>], [printf("%s\n", __func__);],
                  [pgac_cv_funcname_func=yes], [pgac_cv_funcname_func=no])])
if test x"$pgac_cv_funcname_func" = xyes ; then
  AC_DEFINE(HAVE_FUNCNAME__FUNC, 1,
            [Define to 1 if your compiler understands __func__.])
fi

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

dnl Additional gcc tuning
if test x"$GCC" = xyes; then
  AC_MSG_CHECKING([for working warning switches])
  good_CFLAGS="$CFLAGS"
  warnings=""
  flags="-Wall -Wextra"
  # turn off noise from Wextra
  flags="$flags -Wno-unused-parameter -Wno-missing-field-initializers"
  # Wextra does not turn those on?
  flags="$flags -Wmissing-prototypes -Wpointer-arith -Wendif-labels"
  flags="$flags -Wdeclaration-after-statement -Wold-style-definition"
  flags="$flags -Wstrict-prototypes -Wundef -Wformat -Wnonnull -Wstrict-overflow"
  flags="$flags -Wformat-security -Wformat-nonliteral -Wformat-extra-args -Wformat-contains-nul"
  for f in $flags; do
    CFLAGS="$good_CFLAGS $warnings $f"
    AC_COMPILE_IFELSE([void foo(void){}], [warnings="$warnings $f"])
  done
  CFLAGS="$good_CFLAGS $warnings"
  AC_MSG_RESULT([$warnings])
fi

dnl Checks for header files.
AC_CHECK_HEADERS([crypt.h sys/param.h sys/socket.h sys/uio.h libgen.h pwd.h grp.h])
AC_CHECK_HEADERS([sys/resource.h sys/wait.h sys/un.h arpa/inet.h])
AC_CHECK_HEADERS([netinet/in.h netinet/tcp.h netdb.h regex.h])

dnl ucred.h may have prereqs
AC_CHECK_HEADERS([ucred.h sys/ucred.h], [], [], [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_BIGENDIAN
AC_SYS_LARGEFILE
AC_TYPE_PID_T
AC_TYPE_SIZE_T

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
AC_CHECK_FUNCS(strlcpy strlcat getpeereid getpeerucred basename)
AC_SEARCH_LIBS(crypt, crypt)
AC_SEARCH_LIBS(clock_gettime, rt)
AC_SEARCH_LIBS(getsockname, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(hstrerror, resolv)
AC_SEARCH_LIBS(regcomp, regex, [], AC_MSG_ERROR([regcomp not found]))
AC_CHECK_FUNCS(crypt inet_ntop lstat)

dnl Find libevent
AC_MSG_CHECKING([for libevent])
AC_ARG_WITH(libevent,
  AC_HELP_STRING([--with-libevent=prefix],[Specify where libevent is installed]),
  [ test "$withval" = "no" && AC_MSG_ERROR("cannot work without libevent")
    CPPFLAGS="$CPPFLAGS -I$withval/include"
    LDFLAGS="$LDFLAGS -L$withval/lib" ])
LIBS="-levent $LIBS"
AC_LINK_IFELSE([
  #include <sys/types.h>
  #include <sys/time.h>
  #include <stdio.h>
  #include <event.h>
  int main(void) {
    struct event ev;
    event_init();
    event_set(&ev, 1, EV_READ, NULL, NULL);
    /* this checks for 1.2+ but next we check for 1.3b+ anyway */
    /* event_base_free(NULL); */
  } ],
[AC_MSG_RESULT([found])],
[AC_MSG_ERROR([not found, cannot proceed])])

dnl libevent < 1.3b crashes on event_base_free()
dnl no good way to check libevent version.  use hack:
dnl evhttp.h defines HTTP_SERVUNAVAIL only since 1.3b
AC_MSG_CHECKING([whether libevent version >= 1.3b])
AC_EGREP_CPP([HTTP_SERVUNAVAIL],
[#include <evhttp.h>
  HTTP_SERVUNAVAIL ],
[AC_MSG_ERROR([no, cannot proceed])],
[AC_MSG_RESULT([yes])])

AC_CHECK_FUNCS(event_loopbreak)

# autoconf does not want to find 'install', if not using automake...
INSTALL=install

AC_ARG_ENABLE(debug,
  AC_HELP_STRING([--disable-debug],[strip binary]),
  [], [enable_debug=yes])
AC_MSG_CHECKING([whether to build debug binary])
if test "$enable_debug" = "yes"; then
  LDFLAGS="-g $LDFLAGS"
  BININSTALL="$INSTALL"
  AC_MSG_RESULT([yes])
else
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

