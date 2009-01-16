
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
DATA = README NEWS AUTHORS etc/pgbouncer.ini etc/userlist.txt Makefile \
       config.mak.in include/config.h.in \
       configure configure.ac debian/packages debian/changelog doc/Makefile \
       test/Makefile test/asynctest.c test/conntest.sh test/ctest6000.ini \
       test/ctest7000.ini test/run-conntest.sh test/stress.py test/test.ini \
       test/test.sh test/userlist.txt etc/example.debian.init.sh doc/fixman.py \
       win32/eventmsg.mc win32/eventmsg.rc win32/MSG00001.bin \
       win32/Makefile win32/pgbevent.c \
       win32/win32support.c win32/win32support.h
DIRS = doc etc include src debian test win32

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
exe = $(builddir)/pgbouncer$(EXT)

CPPCFLAGS += -I$(srcdir)/include

ifneq ($(builddir),$(srcdir))
CPPCFLAGS += -I$(builddir)/include
endif

ifeq ($(enable_debug),yes)
CPPCFLAGS += -DDBGVER="\"compiled by <$${USER}@`hostname`> at `date '+%Y-%m-%d %H:%M:%S'`\""
endif

ifeq ($(PORTNAME),win32)

EXT = .exe

CPPFLAGS += -I$(srcdir)/win32
WSRCS = win32support.c
WHDRS = win32support.h
WOBJS = $(WSRCS:.c=.o)
srcs += $(srcdir)/win32/win32support.c
hdrs += $(srcdir)/win32/win32support.h
objs += $(builddir)/lib/win32support.o

dll = $(builddir)/pgbevent.dll
dlldef = $(builddir)/lib/pgbevent.def
dllobjs = $(builddir)/lib/eventmsg.o $(builddir)/lib/pgbevent.o

DEFFLAGS = --export-all-symbols -A

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
all: $(exe) $(dll) doc-all

# final executable
$(exe): $(builddir)/config.mak $(objs)
	$(E) "	LD" $@
	$(Q) $(CC) -o $@ $(LDFLAGS) $(objs) $(LIBS)

# objects depend on all the headers
$(builddir)/lib/%.o: $(srcdir)/src/%.c $(builddir)/config.mak $(hdrs)
	@mkdir -p $(builddir)/lib
	$(E) "	CC" $<
	$(Q) $(CC) -c -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)

$(builddir)/lib/%.o: $(srcdir)/win32/%.c $(builddir)/config.mak $(hdrs)
	@mkdir -p $(builddir)/lib
	$(E) "	CC" $<
	$(Q) $(CC) -c -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)

# install binary and other stuff
install: $(exe) doc-install
	mkdir -p $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(docdir)
	$(BININSTALL) -m 755 $(exe) $(DESTDIR)$(bindir)
	$(INSTALL) -m 644 $(srcdir)/etc/pgbouncer.ini  $(DESTDIR)$(docdir)
ifeq ($(PORTNAME),win32)
	$(BININSTALL) -m 755 $(dll) $(DESTDIR)$(bindir)
endif

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
	rm -f $(objs) $(exe) $(dll) $(dlldef) $(dllobjs)

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

ifeq ($(PORTNAME),win32)

$(builddir)/lib/eventmsg.o: $(srcdir)/win32/eventmsg.rc
	$(E) "	WINDRES" $<
	$(Q) $(WINDRES) $< -o $@ --include-dir=$(srcdir)/win32

$(dlldef): $(dllobjs)
	$(E) "	DLLTOOL" $@
	$(Q) $(DLLTOOL) $(DEFFLAGS) --output-def $@ $(dllobjs)

# final executable
$(dll): $(builddir)/config.mak $(dllobjs) $(dlldef)
	$(E) "	DLLWRAP" $@
	$(Q) $(DLLWRAP) --def $(dlldef) -o $@ $(dllobjs)

endif

stripped: $(exe) $(dll)
	$(STRIP) $(exe) $(dll)

