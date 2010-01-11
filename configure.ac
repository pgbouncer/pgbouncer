dnl Process this file with autoconf to produce a configure script.

AC_INIT(pgbouncer, 1.3.3rc1)
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
AC_CHECK_HEADERS([crypt.h regex.h])
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
AC_SEARCH_LIBS(regcomp, regex, [], AC_MSG_ERROR([regcomp not found]))
AC_CHECK_FUNCS(crypt lstat)

dnl Find libevent
levent=yes
AC_MSG_CHECKING([for libevent])
AC_ARG_WITH(libevent,
  AC_HELP_STRING([--with-libevent=prefix],[Specify where libevent is installed]),
  [ if test "$withval" = "no"; then
     levent=no
    else
      CPPFLAGS="$CPPFLAGS -I$withval/include"
      LDFLAGS="$LDFLAGS -L$withval/lib"
    fi
  ])

if test "$levent" = "no"; then
  AC_MSG_RESULT([using usual/event])
  AC_DEFINE(HAVE_EVENT_LOOPBREAK, 1, [usual/event.h has it.])
  have_libevent=no
else # libevent
AC_DEFINE(HAVE_LIBEVENT, 1, [Use real libevent.])
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
have_libevent=yes
fi # libevent
AC_SUBST(have_libevent)

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

