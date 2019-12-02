
PG_CPPFLAGS = -I$(shell pg_config --includedir)
PG_LIBS = -lpq
PG_LDFLAGS = -L$(shell pg_config --libdir)

USUAL_DIR = ../lib

SUBLOC = test
DIST_SUBDIRS = ssl

EXTRA_DIST = conntest.sh ctest6000.ini ctest7000.ini run-conntest.sh \
	     hba_test.eval hba_test.rules Makefile \
	     test.ini test.sh stress.py userlist.txt

noinst_PROGRAMS = hba_test
hba_test_CPPFLAGS = -I../include $(LIBEVENT_CFLAGS)
hba_test_LDADD = $(LIBEVENT_LIBS)
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
	./test.sh
	./hba_test
ifeq ($(tls_support),yes)
	$(MAKE) -C ssl check
endif
