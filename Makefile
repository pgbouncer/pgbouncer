
# sources
SRCS = client.c loader.c objects.c pooler.c proto.c sbuf.c server.c util.c \
       admin.c stats.c takeover.c md5.c janitor.c pktbuf.c system.c main.c \
       varcache.c aatree.c hash.c slab.c
HDRS = client.h loader.h objects.h pooler.h proto.h sbuf.h server.h util.h \
       admin.h stats.h takeover.h md5.h janitor.h pktbuf.h system.h bouncer.h \
       list.h mbuf.h varcache.h aatree.h hash.h slab.h iobuf.h

# data & dirs to include in tgz
DOCS = doc/overview.txt doc/usage.txt doc/config.txt doc/todo.txt
MANPAGES = doc/pgbouncer.1 doc/pgbouncer.5
DATA = README NEWS AUTHORS etc/pgbouncer.ini Makefile config.mak.in include/config.h.in \
       configure configure.ac debian/packages debian/changelog doc/Makefile \
       test/Makefile test/asynctest.c test/conntest.sh test/ctest6000.ini \
       test/ctest7000.ini test/run-conntest.sh test/stress.py test/test.ini \
       test/test.sh test/userlist.txt etc/example.debian.init.sh doc/fixman.py
DIRS = doc etc include src debian test

# keep autoconf stuff separate
-include config.mak

# fill values for unconfigured tree
srcdir ?= .
builddir ?= .

# calculate full-path values
OBJS = $(SRCS:.c=.o)
hdrs = $(addprefix $(srcdir)/include/, $(HDRS))
srcs = $(addprefix $(srcdir)/src/, $(SRCS))
objs = $(addprefix $(builddir)/lib/, $(OBJS))
FULL = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
DISTFILES = $(DIRS) $(DATA) $(DOCS) $(srcs) $(hdrs) $(MANPAGES)

CPPCFLAGS += -I$(srcdir)/include

ifneq ($(builddir),$(srcdir))
CPPCFLAGS += -I$(builddir)/include
endif

ifeq ($(enable_debug),yes)
CPPCFLAGS += -DDBGVER="\"compiled by <$${USER}@`hostname`> at `date '+%Y-%m-%d %H:%M:%S'`\""
endif


# Quiet by default, 'make V=1' shows commands
V=0
ifeq ($(V), 0)
Q = @
E = @echo
else
Q = 
E = @true
endif

## actual targets now ##

# default target
all: $(builddir)/pgbouncer doc-all

# final executable
$(builddir)/pgbouncer: $(builddir)/config.mak $(objs)
	$(E) "	LD" $@
	$(Q) $(CC) -o $@ $(LDFLAGS) $(objs) $(LIBS)

# objects depend on all the headers
$(builddir)/lib/%.o: $(srcdir)/src/%.c $(builddir)/config.mak $(hdrs)
	@mkdir -p $(builddir)/lib
	$(E) "	CC" $<
	$(Q) $(CC) -c -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)

# install binary and other stuff
install: $(builddir)/pgbouncer doc-install
	mkdir -p $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(docdir)
	$(BININSTALL) -m 755 $(builddir)/pgbouncer $(DESTDIR)$(bindir)
	$(INSTALL) -m 644 $(srcdir)/etc/pgbouncer.ini  $(DESTDIR)$(docdir)

# create tarfile
tgz: config.mak $(DISTFILES) $(MANPAGES)
	rm -rf $(FULL) $(FULL).tgz
	mkdir $(FULL)
	(for f in $(DISTFILES); do echo $$f; done) | cpio -pm $(FULL)
	tar czf $(FULL).tgz $(FULL)
	rm -rf $(FULL)

doc/pgbouncer.1:
	$(MAKE) -C doc pgbouncer.1

doc/pgbouncer.5:
	$(MAKE) -C doc pgbouncer.5

# create debian package
deb: configure
	yada rebuild
	debuild -uc -us -b

# clean object files
clean: doc-clean
	rm -f $(objs) $(builddir)/pgbouncer

# clean configure results
distclean: clean doc-distclean
	rm -f include/config.h include/config.h.in~ config.log config.status config.mak
	rm -rf lib autom4te*

# clean autoconf results
realclean: distclean doc-realclean
	rm -f aclocal* include/config.h.in configure depcomp install-sh missing
	rm -f tags

# generate configure script and config.h.in
boot:
	autoreconf -i -f
	rm -rf autom4te* include/config.h.in~

# targets can depend on this to force ./configure
$(builddir)/config.mak::
	@test -f $(srcdir)/configure || { \
		 echo "Please run 'make boot && ./configure' first.";exit 1;}
	@test -f $@ || { echo "Please run ./configure first.";exit 1;}

doc-all doc-install doc-clean doc-distclean doc-realclean:
	@if test -d doc; then $(MAKE) -C doc $(subst doc-,,$@) DESTDIR=$(DESTDIR) ;\
	else true; fi


# targets can depend on this to force 'make boot'
configure::
	@test -f $@ || { echo "Please run 'make boot' first.";exit 1;}

# create tags file
tags: $(srcs) $(hdrs)
	if test -f ../libevent/event.h; then \
	  ctags $(srcs) $(hdrs) ../libevent/*.[ch]; \
	else \
	  ctags $(srcs) $(hdrs); \
	fi

# run sparse over code
check: config.mak
	REAL_CC="$(CC)" \
	$(MAKE) clean pgbouncer CC=cgcc

# profiled exe
pgbouncer.pg:
	$(CC) -pg $(DEFS) -g -O2 $(CPPFLAGS) $(LDFLAGS) -o $@ $(srcs) $(LIBS)

pg: pgbouncer.pg

# asm hacks
$(builddir)/lib/%.s: $(srcdir)/src/%.c config.mak $(hdrs)
	@mkdir -p $(builddir)/lib
	$(E) "	CC -S" $<
	$(Q) $(CC) -S -fverbose-asm -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)
asms = $(objs:.o=.s)
asm: $(asms)

