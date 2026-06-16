dnl Process this file with autoconf to produce a configure script.

AC_INIT([libusual],[1.0],[https://libusual.github.io])
AC_CONFIG_SRCDIR(usual/base.h)
AC_CONFIG_HEADERS([usual/config.h])
AC_PREREQ([2.59])

AC_USUAL_INIT

AC_USUAL_PROGRAM_CHECK

LT_INIT

AC_USUAL_HEADER_CHECK

AC_USUAL_TYPE_CHECK

AC_USUAL_FUNCTION_CHECK

AC_USUAL_CASSERT

AC_USUAL_WERROR

AC_USUAL_DEBUG

AC_USUAL_UREGEX

PKG_CHECK_MODULES(LIBEVENT, libevent)

AC_USUAL_GETADDRINFO_A


dnl search for common libraries
# Required for infinite() on FreeBSD:
AC_CHECK_LIB(m, main)
AC_SEARCH_LIBS(clock_gettime, rt)
AC_SEARCH_LIBS(getsockname, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(hstrerror, resolv)

AC_USUAL_TLS

dnl Output findings
AC_CONFIG_FILES([config.mak mk/libusual.pc build.mk])
AC_OUTPUT
