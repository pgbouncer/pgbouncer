
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
	src/scram.c \
	src/server.c \
	src/stats.c \
	src/system.c \
	src/takeover.c \
	src/util.c \
	src/pycall.c \
        src/route_connection.c \
        src/rewrite_query.c \
	src/varcache.c \
	src/common/base64.c \
	src/common/saslprep.c \
	src/common/scram-common.c \
	src/common/unicode_norm.c \
	src/common/wchar.c \
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
	include/scram.h \
	include/server.h \
	include/stats.h \
	include/system.h \
	include/takeover.h \
	include/util.h \
	include/pycall.h \
	include/route_connection.h \
	include/rewrite_query.h \
	include/varcache.h \
	include/common/base64.h \
	include/common/pg_wchar.h \
	include/common/postgres_compat.h \
	include/common/saslprep.h \
	include/common/scram-common.h \
	include/common/unicode_norm.h \
	include/common/unicode_norm_table.h

# pgbouncer_CPPFLAGS = -Iinclude $(CARES_CFLAGS) $(LIBEVENT_CFLAGS) $(TLS_CPPFLAGS)
python_CPPFLAGS = -I/usr/include/python2.7 -I/usr/include/python2.7
pgbouncer_CPPFLAGS = -Iinclude $(CARES_CFLAGS) $(LIBEVENT_CFLAGS) $(TLS_CPPFLAGS) $(python_CPPFLAGS)

# include libusual sources directly
AM_FEATURES = libusual
pgbouncer_EMBED_LIBUSUAL = 1

# docs to install as-is
dist_doc_DATA = README.md NEWS.md etc/pgbouncer.ini etc/userlist.txt

DISTCLEANFILES = config.mak config.status lib/usual/config.h config.log

# files in tgz
EXTRA_DIST = AUTHORS COPYRIGHT Makefile config.mak.in config.sub config.guess \
	     install-sh autogen.sh configure configure.ac \
	     debian/compat debian/changelog debian/control debian/rules debian/copyright \
	     etc/mkauth.py etc/example.debian.init.sh \
	     win32/Makefile \
	     $(LIBUSUAL_DIST)

MAINTAINERCLEANFILES = debian/changelog

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


python_LDFLAGS = -lpthread -ldl -lutil -lm -lpython2.7 -Xlinker -export-dynamic
pgbouncer_LDFLAGS := $(TLS_LDFLAGS)
pgbouncer_LDADD := $(CARES_LIBS) $(LIBEVENT_LIBS) $(TLS_LIBS) $(LIBS) $(python_LDFLAGS)
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

check: all
	etc/optscan.sh
	make -C test check

deb: debian/changelog
	debuild -b -us -uc

debian/changelog: NEWS.md
	echo '$(PACKAGE_TARNAME) ($(PACKAGE_VERSION)-1) unstable; urgency=low' >$@
	echo >>$@
	echo '  * v$(PACKAGE_VERSION)' >>$@
	echo >>$@
	printf ' -- PgBouncer developers <noreply@localhost>  ' >>$@
	date -u -R -d `sed -E -n '/^\*\*/ { s/^.*([0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/;p;q }' $<` >>$@

w32arch = i686-w64-mingw32
w32zip = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)-win32.zip
zip: configure clean
	rm -rf buildexe
	mkdir buildexe
	cd buildexe \
		&& ../configure --host=$(w32arch) --disable-debug \
			--without-openssl \
			--without-cares \
			--enable-evdns \
		&& make \
		&& $(w32arch)-strip pgbouncer.exe pgbevent.dll \
		&& zip pgbouncer.zip pgbouncer.exe pgbevent.dll doc/*.html
	zip -l buildexe/pgbouncer.zip etc/pgbouncer.ini etc/userlist.txt
	mv buildexe/pgbouncer.zip $(w32zip)

zip-up: $(w32zip)
	rsync $(w32zip) pgf:web/pgbouncer/htdocs/win32/

tgz = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz
tgz-up: $(tgz)
	rsync $(tgz) pgf:web/pgbouncer/htdocs/testing/

.PHONY: tags
tags:
	ctags src/*.c include/*.h lib/usual/*.[ch] lib/usual/*/*.[ch]

htmls:
	for f in *.md doc/*.md; do \
		mkdir -p html && $(PANDOC) $$f -o html/`basename $$f`.html; \
	done

