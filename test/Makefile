
#PGINC = -I$(shell pg_config --includedir)
#PGLIB = -L$(shell pg_config --libdir)
#CPPFLAGS += -I../include -I../lib $(PGINC)
#LDFLAGS += $(PGLIB)
#LIBS := -lpq $(LIBS)
#ifeq ($(PORTNAME),win32)
#CPPFLAGS += -I../win32
#endif

USUAL_DIR = ../lib

noinst_PROGRAMS = hba_test
hba_test_CPPFLAGS = -I../include
hba_test_CFLAGS = -O0
hba_test_SOURCES = hba_test.c ../src/hba.c ../src/util.c
hba_test_EMBED_LIBUSUAL = 1

AM_FEATURES = libusual

include ../config.mak
include ../lib/mk/antimake.mk

all: run_test

run_test: hba_test
	./hba_test

