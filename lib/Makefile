AM_CPPFLAGS = -I$(builddir) -I$(srcdir) $(TLS_CPPFLAGS)
AM_LDFLAGS = $(TLS_LDFLAGS)
AM_LIBS = $(TLS_LIBS)

# main target
lib_LTLIBRARIES = libusual.la

# sources that are not always built
EXTRA_libusual_la_SOURCES = usual/pgsocket.h usual/pgsocket.c

internal_headers = usual/pgutil_kwlookup.h \
		   usual/tls/tls_compat.h \
		   usual/tls/tls_internal.h

# sources not in tar.gz
nodist_EXTRA_libusual_la_SOURCES = usual/config.h

# regular source files
libusual_la_SOURCES = usual/config.h.in \
	usual/aatree.h usual/aatree.c \
	usual/base.h usual/base.c usual/base_win32.h \
	usual/bits.h \
	usual/cbtree.h usual/cbtree.c \
	usual/cfparser.h usual/cfparser.c \
	usual/config_msvc.h \
	usual/crypto/chacha.h usual/crypto/chacha.c \
	usual/crypto/csrandom.h usual/crypto/csrandom.c \
	usual/crypto/digest.h usual/crypto/digest.c \
	usual/crypto/entropy.h usual/crypto/entropy.c \
	usual/crypto/hmac.h usual/crypto/hmac.c \
	usual/crypto/keccak.h usual/crypto/keccak.c \
	usual/crypto/keccak_prng.h usual/crypto/keccak_prng.c \
	usual/crypto/md5.h usual/crypto/md5.c \
	usual/crypto/sha1.h usual/crypto/sha1.c \
	usual/crypto/sha256.h usual/crypto/sha256.c \
	usual/crypto/sha512.h usual/crypto/sha512.c \
	usual/crypto/sha3.h usual/crypto/sha3.c \
	usual/ctype.h \
	usual/cxalloc.h usual/cxalloc.c \
	usual/cxextra.h usual/cxextra.c \
	usual/daemon.h usual/daemon.c \
	usual/endian.h \
	usual/err.h usual/err.c \
	usual/fileutil.h usual/fileutil.c \
	usual/fnmatch.h usual/fnmatch.c \
	usual/getopt.h usual/getopt.c \
	usual/hashing/crc32.h usual/hashing/crc32.c \
	usual/hashing/lookup3.h usual/hashing/lookup3.c \
	usual/hashing/memhash.h usual/hashing/memhash.c \
	usual/hashing/siphash.h usual/hashing/siphash.c \
	usual/hashing/spooky.h usual/hashing/spooky.c \
	usual/hashing/xxhash.h usual/hashing/xxhash.c \
	usual/hashtab-impl.h \
	usual/heap.h usual/heap.c \
	usual/json.h usual/json.c \
	usual/list.h usual/list.c \
	usual/logging.h usual/logging.c \
	usual/mbuf.h usual/mbuf.c \
	usual/mdict.h usual/mdict.c \
	usual/mempool.h usual/mempool.c \
	usual/misc.h \
	usual/netdb.h usual/netdb.c \
	usual/pgutil.h usual/pgutil.c usual/pgutil_kwlookup.h \
	usual/psrandom.h usual/psrandom.c \
	usual/pthread.h usual/pthread.c \
	usual/regex.h usual/regex.c \
	usual/safeio.h usual/safeio.c \
	usual/shlist.h \
	usual/signal.h usual/signal.c \
	usual/slab.h usual/slab.c \
	usual/socket.h usual/socket.c usual/socket_ntop.c usual/socket_pton.c usual/socket_win32.h \
	usual/statlist.h \
	usual/string.h usual/string.c \
	usual/strpool.h usual/strpool.c \
	usual/talloc.h usual/talloc.c \
	usual/time.h usual/time.c \
	usual/tls/tls.h usual/tls/tls.c usual/tls/tls_internal.h \
	usual/tls/tls_compat.h usual/tls/tls_compat.c usual/tls/tls_peer.c \
	usual/tls/tls_client.c usual/tls/tls_config.c usual/tls/tls_ocsp.c \
	usual/tls/tls_server.c usual/tls/tls_util.c usual/tls/tls_verify.c \
	usual/tls/tls_cert.h usual/tls/tls_cert.c usual/tls/tls_conninfo.c \
	usual/utf8.h usual/utf8.c \
	usual/wchar.h usual/wchar.c

# we want to filter headers, so cannot use usual install method via _HEADERS
USUAL_HEADERS = $(filter-out $(internal_headers), \
		$(filter %.h,$(libusual_la_SOURCES) $(nodist_EXTRA_libusual_la_SOURCES)))

# define aclocal destination
aclocaldir = ${datarootdir}/aclocal
AM_DESTINATIONS = aclocal

# other files
dist_pkgdata_SCRIPTS = find_modules.sh
dist_aclocal_DATA = m4/usual.m4 m4/antimake.m4

# test program for link-test
noinst_PROGRAMS = test/compile
test_compile_SOURCES = test/compile.c
test_compile_LDADD = libusual.la
test_compile_LIBS = $(TLS_LIBS)

# extra clean files
DISTCLEANFILES = config.log build.mk config.status libtool config.mak
MAINTAINERCLEANFILES = build.mk.in configure install-sh ltmain.sh config.sub config.guess

# files for .tgz that are not mentioned in sources
EXTRA_DIST = $(MAINTAINERCLEANFILES)

# we dont build test subdir by default, but want to include in .tgz
DIST_SUBDIRS = test

# non-recursive subdir
EMBED_SUBDIRS = mk

#
# Launch Antimake
#
include build.mk

# filter headers when installing
install-local:
	@$(MKDIR_P) $(DESTDIR)$(includedir)/usual
	@$(MKDIR_P) $(DESTDIR)$(includedir)/usual/hashing
	@$(MKDIR_P) $(DESTDIR)$(includedir)/usual/crypto
	@$(MKDIR_P) $(DESTDIR)$(includedir)/usual/tls
	@for hdr in $(USUAL_HEADERS); do \
		echo Filtering $$hdr; \
		$(SED) -f mk/safe-headers.sed $$hdr \
		> $(DESTDIR)$(includedir)/$$hdr; \
	done

# Give proper error message
build.mk:
	@echo "Please run ./configure first"
	@exit 1

%.pc: %.pc.in config.status
	./config.status --file $@

# run sparse over code
sparse: config.mak
	REAL_CC="$(CC)" \
	$(MAKE) clean libusual.a CC="cgcc -Wsparse-all -Wno-transparent-union"

# generate api documentation
dox:
	rm -rf doc/html/mk
	#rm -rf mk/temos/html
	doxygen doc/Doxyfile
	$(MAKE) -C mk/temos html
	cp -rp mk/temos/html doc/html/mk

#
# rest is for pgutil_kwlookup generation
#

PG_CONFIG ?= pg_config
KWLIST = $(shell $(PG_CONFIG) --includedir-server)/parser/kwlist.h

# requires 8.4+
kws:
	@test -f "$(KWLIST)" || { echo "kwlist.h not found"; exit 1; }
	./mk/gen-pgutil_kwlookup_gp.sh "$(KWLIST)" >> usual/pgutil_kwlookup.gp

kwh: usual/pgutil_kwlookup.g
	./mk/gen-pgutil_kwlookup_h.sh $^ > usual/pgutil_kwlookup.h

sizes: all
	size `find .objs -name '.libs' -prune -o -name '*.o' -print | sort`

%.s: %.c
	$(CC) -S $(DEFS) $(CFLAGS) $(CPPFLAGS) -I. $< -o - | cleanasm > $@

.PHONY: tags
tags:
	ctags $(libusual_la_SOURCES)

.PHONY: nodoc
nodoc:
	@for hdr in `find usual -name '*.h'`; do \
	  grep -q "$$hdr" doc/mainpage.dox || echo "$$hdr" ; \
	done

check: all
	$(MAKE) -C test check
