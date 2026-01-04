AM_FEATURES = libusual

SUBLOC = test
DIST_SUBDIRS = attregex

USUAL_DIR = $(abs_top_srcdir)

regtest_system_SOURCES = \
	test_aatree.c \
	test_base.c \
	test_bits.c \
	test_cbtree.c \
	test_cfparser.c \
	test_crypto.c \
	test_ctype.c \
	test_cxalloc.c \
	test_endian.c \
	test_fileutil.c \
	test_fnmatch.c \
	test_getopt.c \
	test_hashing.c \
	test_hashtab.c \
	test_heap.c \
	test_json.c \
	test_list.c \
	test_mdict.c \
	test_netdb.c \
	test_pgutil.c \
	test_psrandom.c \
	test_regex.c \
	test_shlist.c \
	test_socket.c \
	test_string.c \
	test_strpool.c \
	test_talloc.c \
	test_time.c \
	test_tls.c \
	test_utf8.c \
	test_wchar.c \
	\
	test_common.c test_common.h \
	tinytest.c tinytest.h tinytest_macros.h

# build regtest_system against actual library
regtest_system_LDADD = -static ../libusual.la
regtest_system_LIBS = $(TLS_LIBS) $(LIBEVENT_LIBS) $(LIBS)
regtest_system_LDFLAGS = $(TLS_LDFLAGS)
regtest_system_CPPFLAGS = -I.. -I. $(TLS_CPPFLAGS) $(LIBEVENT_CFLAGS)

# build regtest_compat as embedded project
regtest_compat_EMBED_LIBUSUAL = 1
regtest_compat_CPPFLAGS := -I.. -I. -DUSUAL_TEST_CONFIG $(TLS_CPPFLAGS) $(LIBEVENT_CFLAGS)
regtest_compat_LIBS = $(TLS_LIBS) $(LIBEVENT_LIBS) $(LIBS)
regtest_compat_LDFLAGS = $(TLS_LDFLAGS)
regtest_compat_SOURCES := $(regtest_system_SOURCES)
nodist_regtest_compat_SOURCES = test_config.h

connect_SOURCES = connect-tls.c
connect_LDADD = -static ../libusual.la
connect_LIBS = $(TLS_LIBS) $(LIBS)
connect_LDFLAGS = $(TLS_LDFLAGS)
connect_CPPFLAGS = -I.. -I. $(TLS_CPPFLAGS)

EXTRA_DIST = Makefile tinytest_demo.c force_compat.sed test_cfparser.ini

noinst_PROGRAMS = regtest_system connect
EXTRA_PROGRAMS = regtest_compat

include ../build.mk

test_config.h: force_compat.sed ../usual/config.h
	$(E) "	GEN-COMPAT" $@
	$(Q) sed -f $^ > $@

clean: clean-local

clean-local:
	$(Q) $(RM) -r fmod_test

check run:
	@echo CC=$(CC) CFLAGS=$(CFLAGS)
	$(MAKE) -C ..
	$(MAKE) all regtest_system regtest_compat
	./regtest_system
	./regtest_compat

.PHONY: tags
tags:
	ctags $(regtest_system_SOURCES)
