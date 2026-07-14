
include config.mak

bin_PROGRAMS = pgbouncer

pgbouncer_SOURCES = \
	src/admin.c \
	src/client.c \
	src/dnslookup.c \
	src/hba.c \
	src/janitor.c \
	src/ldapauth.c \
	src/loader.c \
	src/messages.c \
	src/main.c \
	src/objects.c \
	src/pam.c \
	src/gss.c \
	src/pktbuf.c \
	src/pooler.c \
	src/proto.c \
	src/prepare.c \
	src/sbuf.c \
	src/scram.c \
	src/server.c \
	src/stats.c \
	src/system.c \
	src/takeover.c \
	src/util.c \
	src/varcache.c \
	src/common/sha2.c \
	src/common/base64.c \
	src/common/bool.c \
	src/common/cryptohash.c \
	src/common/hmac.c \
	src/common/pgstrcasecmp.c \
	src/common/saslprep.c \
	src/common/scram-common.c \
	src/common/string.c \
	src/common/unicode_norm.c \
	src/common/wchar.c \
	include/admin.h \
	include/bouncer.h \
	include/client.h \
	include/dnslookup.h \
	include/hba.h \
	include/iobuf.h \
	include/janitor.h \
	include/ldapauth.h \
	include/loader.h \
	include/messages.h \
	include/objects.h \
	include/pam.h \
	include/gss.h \
	include/pktbuf.h \
	include/pooler.h \
	include/proto.h \
	include/prepare.h \
	include/sbuf.h \
	include/scram.h \
	include/server.h \
	include/stats.h \
	include/system.h \
	include/takeover.h \
	include/util.h \
	include/varcache.h \
	include/common/ascii.h \
	include/common/base64.h \
	include/common/builtins.h \
	include/common/cryptohash.h \
	include/common/hmac.h \
	include/common/pg_wchar.h \
	include/common/postgres_compat.h \
	include/common/protocol.h \
	include/common/saslprep.h \
	include/common/scram-common.h \
	include/common/sha2.h \
	include/common/sha2_int.h \
	include/common/simd.h \
	include/common/string.h \
	include/common/unicode_east_asian_fw_table.h \
	include/common/unicode_nonspacing_table.h \
	include/common/unicode_norm.h \
	include/common/unicode_norm_table.h \
	include/common/uthash.h \
	include/common/uthash_lowercase.h

pgbouncer_CPPFLAGS = -Iinclude $(CARES_CFLAGS) $(LIBEVENT_CFLAGS) $(TLS_CPPFLAGS)

# include libusual sources directly
AM_FEATURES = libusual
pgbouncer_EMBED_LIBUSUAL = 1

# docs to install as-is
dist_doc_DATA = README.md NEWS.md \
	etc/pgbouncer-minimal.ini \
	etc/pgbouncer.ini \
	etc/pgbouncer.service \
	etc/pgbouncer.socket \
	etc/userlist.txt

DISTCLEANFILES = config.mak config.status lib/usual/config.h config.log

DIST_SUBDIRS = doc test
dist_man_MANS = doc/pgbouncer.1 doc/pgbouncer.5

pgbouncer_LDFLAGS := $(TLS_LDFLAGS)
pgbouncer_LDADD := $(CARES_LIBS) $(LIBEVENT_LIBS) $(TLS_LIBS) $(LIBS)
LIBS :=

#
# win32
#

EXTRA_pgbouncer_SOURCES = win32/win32support.c win32/win32support.h win32/win32ver.rc
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
AM_LANG_RC_COMPILE = $(WINDRES) $< -o $@ --include-dir=$(srcdir)/win32 --include-dir=lib
AM_LANG_RC_LINK = false

#
# now load antimake
#

# disable dist target from antimake
AM_DIST_DEFAULT =

USUAL_DIR = lib

abs_top_srcdir ?= $(CURDIR)
include $(abs_top_srcdir)/lib/mk/antimake.mk

config.mak:
	@echo "Please run ./configure"
	@exit 1

#
# dist
# (adapted from PostgreSQL)
#

distdir = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
PG_GIT_REVISION = HEAD
GIT = git

EXTRA_DIST = config.guess config.sub configure install-sh lib/usual/config.h.in

dist: $(distdir).tar.gz

$(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.gz:
	$(GIT) -C $(srcdir) -c core.autocrlf=false archive --format tar.gz -9 --prefix $(distdir)/ $(PG_GIT_REVISION) -o $(abs_top_builddir)/$@ $(foreach file,$(EXTRA_DIST),--prefix $(distdir)/$(dir $(file)) --add-file=$(file)) --prefix $(distdir)/

#
# test
#

PYTEST = $(shell command -v pytest || echo '$(PYTHON) -m pytest')

CONCURRENCY = auto
PYTEST_FLAGS = -r s

check: all
	etc/optscan.sh
	if [ $(CONCURRENCY) = 1 ]; then \
		PYTHONIOENCODING=utf8 $(PYTEST) $(PYTEST_FLAGS); \
	else \
		PYTHONIOENCODING=utf8 $(PYTEST) -n $(CONCURRENCY) $(PYTEST_FLAGS); \
	fi
	$(MAKE) -C test check

w32zip = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)-windows-$(host_cpu).zip
zip: $(w32zip)

$(w32zip): pgbouncer.exe pgbevent.dll etc/pgbouncer.ini etc/userlist.txt README.md COPYRIGHT
	rm -rf $(basename $@)
	mkdir $(basename $@)
	cp $^ $(basename $@)
	$(STRIP) $(addprefix $(basename $@)/,$(filter %.exe %.dll,$(^F)))
	zip -MM $@ $(addprefix $(basename $@)/,$(filter %.exe %.dll,$(^F)))
# NB: zip -l for text files for end-of-line conversion
	zip -MM -l $@ $(addprefix $(basename $@)/,$(filter-out %.exe %.dll,$(^F)))

.PHONY: tags
tags:
	ctags src/*.c include/*.h lib/usual/*.[ch] lib/usual/*/*.[ch]

htmls:
	for f in *.md doc/*.md; do \
		mkdir -p html && $(PANDOC) $$f -o html/`basename $$f`.html; \
	done

doc/pgbouncer.1 doc/pgbouncer.5:
	$(MAKE) -C doc $(@F)

# Formatting and linting live in a build-system-independent script so the same
# logic is shared with meson (`meson compile -C build format` etc.); these
# targets just forward to it.
lint:
	dev/format.sh lint

format-check:
	dev/format.sh check

format:
	dev/format.sh fix

format-c:
	dev/format.sh fix-c

format-python:
	dev/format.sh fix-python
