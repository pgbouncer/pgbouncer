
include config.mak

bin_PROGRAMS = pgbouncer

pgbouncer_SOURCES = \
	src/admin.c \
	src/client.c \
	src/dnslookup.c \
	src/janitor.c \
	src/loader.c \
	src/main.c \
	src/objects.c \
	src/pktbuf.c \
	src/pooler.c \
	src/proto.c \
	src/sbuf.c \
	src/server.c \
	src/stats.c \
	src/system.c \
	src/takeover.c \
	src/util.c \
	src/varcache.c \
	include/admin.h \
	include/bouncer.h \
	include/client.h \
	include/dnslookup.h \
	include/iobuf.h \
	include/janitor.h \
	include/loader.h \
	include/objects.h \
	include/pktbuf.h \
	include/pooler.h \
	include/proto.h \
	include/sbuf.h \
	include/server.h \
	include/stats.h \
	include/system.h \
	include/takeover.h \
	include/util.h \
	include/varcache.h

# docs to install as-is
dist_doc_DATA = doc/overview.txt doc/usage.txt doc/config.txt doc/todo.txt doc/faq.txt \
		README NEWS etc/pgbouncer.ini etc/userlist.txt

# manpages
man_MANS = doc/pgbouncer.1 doc/pgbouncer.5

# files in tgz
EXTRA_DIST = AUTHORS COPYRIGHT Makefile \
	     config.mak.in etc/mkauth.py \
	     config.sub config.guess install-sh autogen.sh \
	     configure configure.ac debian/packages debian/changelog doc/Makefile \
	     test/Makefile test/asynctest.c test/conntest.sh test/ctest6000.ini \
	     test/ctest7000.ini test/run-conntest.sh test/stress.py test/test.ini \
	     test/test.sh test/userlist.txt etc/example.debian.init.sh doc/fixman.py \
	     win32/Makefile

ifeq ($(enable_debug),yes)
CPPFLAGS += -DDBGVER="\"compiled by <$${USER}@`hostname`> at `date '+%Y-%m-%d %H:%M:%S'`\""
endif

#
# win32
#

pgbouncer_LIBS := $(LIBS)
LIBS :=

EXTRA_pgbouncer_SOURCES = win32/win32support.c win32/win32support.h
EXTRA_PROGRAMS = pgbevent
ifeq ($(PORTNAME),win32)
pgbouncer_CPPFLAGS = -I$(srcdir)/win32
pgbouncer_SOURCES += $(EXTRA_pgbouncer_SOURCES)
bin_PROGRAMS += pgbevent
endif

pgbevent_SOURCES = win32/pgbevent.c win32/eventmsg.rc \
		   win32/eventmsg.mc win32/MSG00001.bin
pgbevent_EXT = .dll
pgbevent_LINK = $(CC) -shared -Wl,--export-all-symbols -Wl,--add-stdcall-alias -o $@ $^

# .rc->.o
AM_LANGUAGES = RC
AM_LANG_RC_SRCEXTS = .rc
AM_LANG_RC_COMPILE = $(WINDRES) $< -o $@ --include-dir=$(srcdir)/win32
AM_LANG_RC_LINK = false

#
# now load antimake
#

USUAL_DIR = $(top_srcdir)/lib
pgbouncer_EMBED_LIBUSUAL = 1
include $(abs_top_srcdir)/lib/mk/antimake.mk

