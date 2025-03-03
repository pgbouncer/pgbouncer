
PG_CPPFLAGS = -I$(shell pg_config --includedir)
PG_LIBS = -lpq
PG_LDFLAGS = -L$(shell pg_config --libdir)

USUAL_DIR = ../lib

SUBLOC = test
DIST_SUBDIRS = ssl

EXTRA_DIST = conntest.sh ctest6000.ini ctest7000.ini run-conntest.sh \
	     hba_test.eval hba_test.rules Makefile pgident.conf \
	     test.ini stress.py userlist.txt pgbouncer_hba.conf start_openldap_server.sh \
	     __init__.py conftest.py utils.py \
	     test_admin.py test_auth.py test_cancel.py test_copy.py test_limits.py \
	     test_load_balance_hosts.py test_misc.py test_no_database.py \
	     test_no_user.py test_operations.py test_peering.py test_prepared.py \
	     test_timeouts.py test_tls.py test_replication.py


UTHASH = ../uthash
noinst_PROGRAMS = hba_test
hba_test_CPPFLAGS = -I../include $(LIBEVENT_CFLAGS) -I$(UTHASH)/src
hba_test_LDADD = $(LIBEVENT_LIBS) $(TLS_LIBS)
hba_test_CFLAGS = -O0
hba_test_SOURCES = hba_test.c ../src/hba.c ../src/util.c
hba_test_EMBED_LIBUSUAL = 1

EXTRA_PROGRAMS = asynctest
asynctest_CPPFLAGS = -I../include $(PG_CPPFLAGS) $(LIBEVENT_CFLAGS)
asynctest_LDFLAGS = $(PG_LDFLAGS)
asynctest_LDADD = $(PG_LIBS) $(LIBEVENT_LIBS)
asynctest_SOURCES = asynctest.c
asynctest_EMBED_LIBUSUAL = 1

AM_FEATURES = libusual


include ../config.mak
include ../lib/mk/antimake.mk

check: all
	./hba_test
