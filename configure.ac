dnl Process this file with autoconf to produce a configure script.

AC_INIT([PgBouncer],
        [1.20.0],
        [https://github.com/pgbouncer/pgbouncer/issues], [],
        [https://www.pgbouncer.org/])
AC_CONFIG_SRCDIR(src/janitor.c)
AC_CONFIG_HEADERS([lib/usual/config.h])
AC_PREREQ([2.59])

dnl basic init
AC_USUAL_INIT

dnl Checks for programs.
AC_USUAL_PROGRAM_CHECK

PKG_PROG_PKG_CONFIG

AC_CHECK_PROGS(PANDOC, pandoc, pandoc)
AC_CHECK_PROGS(PYTHON, [python3 python], python3)

dnl check for windows tools
if test "$PORTNAME" = "win32"; then
  AC_CHECK_TOOL([WINDRES], [windres])
  AC_CHECK_TOOL([DLLWRAP], [dllwrap])
  AC_CHECK_TOOL([DLLTOOL], [dlltool])
fi
AC_CHECK_TOOL([STRIP], [strip])

dnl Checks for header files.
AC_USUAL_HEADER_CHECK
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
AC_SEARCH_LIBS(clock_gettime, rt)
AC_SEARCH_LIBS(getsockname, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(hstrerror, resolv)
AC_CHECK_FUNCS(lstat)

dnl Find libevent
PKG_CHECK_MODULES(LIBEVENT, libevent)

dnl Check for PAM authentication support
pam_support=no
AC_ARG_WITH(pam,
  AS_HELP_STRING([--with-pam], [build with PAM support]),
  [ PAM=
    if test "$withval" != no; then
        have_pthreads=no
        # Look for PAM header and lib
        AC_CHECK_HEADERS(security/pam_appl.h, [have_pam_header=t])
        AC_CHECK_HEADERS(pthread.h, [have_pthreads=yes])
        AC_SEARCH_LIBS(pam_start, pam, [have_libpam=t])
        AC_SEARCH_LIBS(pthread_create, pthread, [], [have_pthreads=no])
        if test x"${have_pthreads}" != xyes; then
           AC_MSG_ERROR([pthread library should be available for PAM support])
        fi
        if test x"${have_pam_header}" != x -a x"${have_libpam}" != x -a x"${have_pthreads}" = xyes; then
          pam_support=yes
          AC_DEFINE(HAVE_PAM, 1, [PAM support])
        fi
    fi
  ], [])

dnl Check for systemd support
AC_MSG_CHECKING([whether to build with systemd support])
AC_ARG_WITH(systemd,
            [AS_HELP_STRING([--with-systemd], [build with systemd support])],
            [if test "$withval" != no; then with_systemd=yes; else with_systemd=no; fi],
            [with_systemd=no])
AC_MSG_RESULT([$with_systemd])
AC_SUBST(with_systemd)[]dnl
if test "$with_systemd" = yes; then
  AC_DEFINE([USE_SYSTEMD], 1, [Define to build with systemd support. (--with-systemd)])
  AC_CHECK_HEADER(systemd/sd-daemon.h, [], [AC_MSG_ERROR([header file <systemd/sd-daemon.h> is required for systemd support])])
  AC_SEARCH_LIBS(sd_notify, systemd)
fi

##
## DNS backend
##

# make sure all vars are set
use_cares=no
use_udns=no
use_evdns=no

dnl Find c-ares
AC_MSG_CHECKING([whether to use c-ares for DNS lookups])
AC_ARG_WITH(cares,
  AS_HELP_STRING([--with-cares@<:@=PREFIX@:>@], [build with c-ares support]),
  [ if test "$withval" = "no"; then
      use_cares=no
    elif test "$withval" = "yes"; then
      use_cares="$withval"
      CARES_CFLAGS=""
      CARES_LIBS="-lcares"
    elif test "$withval" = "auto"; then
      use_cares="$withval"
    else
      use_cares=yes
      CARES_CFLAGS="-I$withval/include"
      CARES_LIBS="-L$withval/lib -lcares"
    fi
  ], [use_cares=auto])
AC_MSG_RESULT([$use_cares])

if test "$use_cares" = "auto"; then
  PKG_CHECK_MODULES(CARES, [libcares >= 1.6.0], [use_cares=yes], [use_cares=no])
fi

if test "$use_cares" = "yes"; then
  AC_DEFINE(USE_CARES, 1, [Use c-ares for name resolution.])

  tmp_CFLAGS="$CFLAGS"
  tmp_LIBS="$LIBS"
  CFLAGS="$CARES_CFLAGS $CFLAGS"
  LIBS="$CARES_LIBS $LIBS"
  # does it support SOA parse
  AC_CHECK_FUNCS(ares_parse_soa_reply)
  # portability substitute for arpa/nameser.h, needed mainly for Windows
  AC_CHECK_HEADERS([ares_nameser.h])
  LIBS="$tmp_LIBS"
  CFLAGS="$tmp_CFLAGS"

else # !cares

dnl Find libudns
AC_MSG_CHECKING([whether to use libudns])
AC_ARG_WITH(udns,
  AS_HELP_STRING([--with-udns@<:@=PREFIX@:>@], [build with udns support]),
  [ if test "$withval" = "no"; then
      use_udns=no
    elif test "$withval" = "yes"; then
      use_udns=yes
    else
      use_udns=yes
      CPPFLAGS="$CPPFLAGS -I$withval/include"
      LDFLAGS="$LDFLAGS -L$withval/lib"
    fi
  ], [])
AC_MSG_RESULT([$use_udns])

if test "$use_udns" = "yes"; then
  AC_DEFINE(USE_UDNS, 1, [Use UDNS for name resolution.])
  LIBS="-ludns $LIBS"
  AC_MSG_CHECKING([whether libudns is available])
  AC_LINK_IFELSE([AC_LANG_SOURCE([
    #include <sys/types.h>
    #include <sys/time.h>
    #include <stddef.h>
    #include <udns.h>
    int main(void) {
      struct dns_ctx *ctx = NULL;
      dns_init(ctx, 0);
      dns_reset(ctx);
    } ])],
  [AC_MSG_RESULT([found])],
  [AC_MSG_ERROR([not found, cannot proceed])])

else # !udns

dnl Allow user to override the decision
AC_ARG_ENABLE(evdns, AS_HELP_STRING([--disable-evdns], [do not use libevent for DNS lookups]),
              [use_evdns=$enableval], [use_evdns=yes])
AC_MSG_CHECKING([whether to use libevent for DNS lookups])
if test "$use_evdns" = "yes"; then
  AC_DEFINE(USE_EVDNS, 1, [Use libevent for DNS lookups.])
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

dnl Check if need getaddinfo_a compat
if test "$use_udns.$use_cares.$use_evdns" = "no.no.no"; then
  AC_USUAL_GETADDRINFO_A
fi

fi # !udns

fi # !cares

## end of DNS

AC_USUAL_TLS

AC_USUAL_DEBUG
AC_USUAL_CASSERT
AC_USUAL_WERROR

PACKAGE_VERSION_4B=`echo "${PACKAGE_VERSION}.0" | sed -e 's/\./,/g'`
AC_DEFINE_UNQUOTED(PACKAGE_VERSION_4B, [$PACKAGE_VERSION_4B],
                   [Define to the version of this package for Windows resource file (1,2,3,4).])dnl

dnl Output findings
AC_CONFIG_FILES([config.mak])
AC_OUTPUT

dnl If separate build dir, link Makefile over
test -f Makefile || {
  echo "Linking Makefile"
  ln -s $srcdir/Makefile
}

echo ""
echo "Results:"
dnl Note: Report here should match selection in src/dnslookup.c
if test "$use_cares" = "yes"; then
  echo "  adns    = c-ares"
elif test "$use_udns" = "yes"; then
  echo "  adns    = udns"
elif test "$use_evdns" = "yes"; then
  echo "  adns    = evdns2"
elif test "$ac_cv_usual_glibc_gaia" = "yes"; then
  echo "  adns    = libc"
else
  echo "  adns    = compat"
fi
echo "  pam     = $pam_support"
echo "  systemd = $with_systemd"
echo "  tls     = $tls_support"
echo ""
