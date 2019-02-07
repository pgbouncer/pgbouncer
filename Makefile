
include config.mak

bin_PROGRAMS = pgbouncer

pgbouncer_SOURCES = \
	src/admin.c \
	src/client.c \
	src/dnslookup.c \
	src/hba.c \
	src/janitor.c \
	src/loader.c \
	src/main.c \
	src/objects.c \
	src/pam.c \
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
	include/hba.h \
	include/iobuf.h \
	include/janitor.h \
	include/loader.h \
	include/objects.h \
	include/pam.h \
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

pgbouncer_CPPFLAGS = -Iinclude $(CARES_CFLAGS) $(TLS_CPPFLAGS)

# include libusual sources directly
AM_FEATURES = libusual
pgbouncer_EMBED_LIBUSUAL = 1

# docs to install as-is
dist_doc_DATA = README.md NEWS.md etc/pgbouncer.ini etc/userlist.txt

DISTCLEANFILES = config.mak config.status lib/usual/config.h config.log

DIST_SUBDIRS = doc test
dist_man_MANS = doc/pgbouncer.1 doc/pgbouncer.5

# files in tgz
EXTRA_DIST = AUTHORS COPYRIGHT Makefile config.mak.in config.sub config.guess \
	     install-sh autogen.sh configure configure.ac \
	     debian/compat debian/changelog debian/control debian/rules debian/copyright \
	     etc/mkauth.py etc/example.debian.init.sh \
	     win32/Makefile \
	     $(LIBUSUAL_DIST)

# libusual files (FIXME: list should be provided by libusual...)
LIBUSUAL_DIST = $(filter-out %/config.h, $(sort $(wildcard \
		lib/usual/*.[chg] \
		lib/usual/*/*.[ch] \
		lib/m4/*.m4 \
		lib/usual/config.h.in \
		lib/mk/*.mk \
		lib/mk/antimake.mk lib/mk/antimake.txt \
		lib/mk/install-sh lib/mk/std-autogen.sh \
		lib/README lib/COPYRIGHT \
		lib/find_modules.sh )))

pgbouncer_LDFLAGS := $(TLS_LDFLAGS)
pgbouncer_LDADD := $(CARES_LIBS) $(TLS_LIBS) $(LIBS)
LIBS :=

#
# win32
#

EXTRA_pgbouncer_SOURCES = win32/win32support.c win32/win32support.h
EXTRA_PROGRAMS = pgbevent
ifeq ($(PORTNAME),win32)
pgbouncer_CPPFLAGS += -Iwin32
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

USUAL_DIR = lib

abs_top_srcdir ?= $(CURDIR)
include $(abs_top_srcdir)/lib/mk/antimake.mk

config.mak:
	@echo "Please run ./configure"
	@exit 1

deb:
	debuild -b -us -uc

w32arch = i686-w64-mingw32
w32zip = pgbouncer-$(PACKAGE_VERSION)-win32.zip
zip: configure clean
	rm -rf buildexe
	mkdir buildexe
	cd buildexe \
		&& ../configure --host=$(w32arch) --disable-debug \
			--without-openssl \
			--without-cares \
			--with-libevent=/opt/apps/win32 --enable-evdns \
		&& make \
		&& $(w32arch)-strip pgbouncer.exe pgbevent.dll \
		&& zip pgbouncer.zip pgbouncer.exe pgbevent.dll doc/*.html
	zip -l buildexe/pgbouncer.zip etc/pgbouncer.ini etc/userlist.txt
	mv buildexe/pgbouncer.zip $(w32zip)

zip-up: $(w32zip)
	rsync $(w32zip) pgf:web/pgbouncer/htdocs/win32/

tgz = pgbouncer-$(PACKAGE_VERSION).tar.gz
tgz-up: $(tgz)
	rsync $(tgz) pgf:web/pgbouncer/htdocs/testing/

.PHONY: tags
tags:
	ctags src/*.c include/*.h lib/usual/*.[ch] lib/usual/*/*.[ch]

htmls:
	for f in *.md doc/*.md; do \
		mkdir -p html && $(PANDOC) $$f -o html/`basename $$f`.html; \
	done

doc/pgbouncer.1 doc/pgbouncer.5:
	$(MAKE) -C doc
