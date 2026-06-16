SUBLOC = test/attregex

AM_FEATURES = libusual

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir)
VPATH = $(top_srcdir)
USUAL_DIR = $(top_srcdir)

EXTRA_PROGRAMS = testregex.usual testregex.libc

testregex_usual_SOURCES = testregex.c
testregex_usual_DEFS = -DUSUAL -DUSE_INTERNAL_REGEX
testregex_usual_EMBED_LIBUSUAL = 1

testregex_libc_SOURCES = testregex.c

EXTRA_DIST = Makefile run.sh \
	data/basic.dat \
	data/categorize.dat \
	data/forcedassoc.dat \
	data/interpretation.dat \
	data/leftassoc.dat \
	data/nullsubexpr.dat \
	data/repetition.dat \
	data/rightassoc.dat

test: $(EXTRA_PROGRAMS)

include ../../build.mk
