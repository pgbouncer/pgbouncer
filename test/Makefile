
#PGINC = -I$(shell pg_config --includedir)
#PGLIB = -L$(shell pg_config --libdir)
#CPPFLAGS += -I../include -I../lib $(PGINC)
#LDFLAGS += $(PGLIB)
#LIBS := -lpq $(LIBS)
#ifeq ($(PORTNAME),win32)
#CPPFLAGS += -I../win32
#endif

USUAL_DIR = ../lib

SUBLOC = test
DIST_SUBDIRS = ssl

EXTRA_DIST = conntest.sh ctest6000.ini ctest7000.ini run-conntest.sh \
	     hba_test.eval hba_test.rules Makefile \
	     test.ini test.sh stress.py userlist.txt

noinst_PROGRAMS = hba_test
hba_test_CPPFLAGS = -I../include
hba_test_CFLAGS = -O0
hba_test_SOURCES = hba_test.c ../src/hba.c ../src/util.c
hba_test_EMBED_LIBUSUAL = 1

EXTRA_PROGRAMS = asynctest
asynctest_SOURCES = asynctest.c

AM_FEATURES = libusual


include ../config.mak
include ../lib/mk/antimake.mk

all: run_test

run_test: hba_test
	./hba_test

