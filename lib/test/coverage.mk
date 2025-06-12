AM_FEATURES = libusual
USUAL_DIR = .

noinst_PROGRAMS = covtest

covtest_SOURCES := $(wildcard test/test_*.[ch]) test/tinytest.c test/tinytest.h test/tinytest_macros.h
covtest_CPPFLAGS = -Itest -I. -DUSUAL_TEST_CONFIG
covtest_LDFLAGS =
covtest_EMBED_LIBUSUAL = 1

include build.mk
