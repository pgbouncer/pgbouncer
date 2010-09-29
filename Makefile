
# sources
SRCS = client.c loader.c objects.c pooler.c proto.c sbuf.c server.c util.c \
       admin.c stats.c takeover.c janitor.c pktbuf.c system.c main.c \
       varcache.c dnslookup.c
HDRS = client.h loader.h objects.h pooler.h proto.h sbuf.h server.h util.h \
       admin.h stats.h takeover.h janitor.h pktbuf.h system.h bouncer.h \
       varcache.h iobuf.h dnslookup.h

# data & dirs to include in tgz
DOCS = doc/overview.txt doc/usage.txt doc/config.txt doc/todo.txt
MANPAGES = doc/pgbouncer.1 doc/pgbouncer.5
DATA = README NEWS AUTHORS COPYRIGHT etc/pgbouncer.ini etc/userlist.txt Makefile \
       config.mak.in etc/mkauth.py \
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

local_hdrs = $(addprefix $(srcdir)/include/, $(HDRS))
local_srcs = $(addprefix $(srcdir)/src/, $(SRCS))

USUAL_DIR = $(srcdir)/lib
USUAL_OBJDIR = $(builddir)/obj
USUAL_LOCAL_SRCS = $(local_srcs) $(local_hdrs)
include $(USUAL_DIR)/Setup.mk

# calculate full-path values
OBJS = $(SRCS:.c=.o)
hdrs = $(local_hdrs) $(USUAL_HDRS)
srcs = $(local_srcs)
objs = $(addprefix $(builddir)/obj/, $(OBJS)) $(USUAL_OBJS)
FULL = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
DISTFILES = $(DIRS) $(DATA) $(DOCS) $(local_srcs) $(local_hdrs) $(MANPAGES)
exe = $(builddir)/pgbouncer$(EXT)

CPPFLAGS := -I$(srcdir)/include $(USUAL_CPPFLAGS) $(CPPFLAGS)

ifeq ($(enable_debug),yes)
CPPFLAGS += -DDBGVER="\"compiled by <$${USER}@`hostname`> at `date '+%Y-%m-%d %H:%M:%S'`\""
endif

ifeq ($(PORTNAME),win32)

EXT = .exe

CPPFLAGS += -I$(srcdir)/win32
WSRCS = win32support.c
WHDRS = win32support.h
WOBJS = $(WSRCS:.c=.o)
srcs += $(srcdir)/win32/win32support.c
hdrs += $(srcdir)/win32/win32support.h
objs += $(builddir)/obj/win32support.o

dll = $(builddir)/pgbevent.dll
dlldef = $(builddir)/obj/pgbevent.def
dllobjs = $(builddir)/obj/eventmsg.o $(builddir)/obj/pgbevent.o

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
$(builddir)/obj/%.o: $(srcdir)/src/%.c $(builddir)/config.mak $(hdrs)
	@mkdir -p $(builddir)/obj
	$(E) "	CC" $<
	$(Q) $(CC) -c -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)

$(builddir)/obj/%.o: $(srcdir)/win32/%.c $(builddir)/config.mak $(hdrs)
	@mkdir -p $(builddir)/obj
	$(E) "	CC" $<
	$(Q) $(CC) -c -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)

$(builddir)/obj/%.o: $(USUAL_DIR)/usual/%.c $(builddir)/config.mak $(hdrs)
	@mkdir -p $(builddir)/obj
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
	# tgz for libusual
	cp config.mak configure lib
	rm -f lib/*.tgz
	make -C lib tgz
	# now create new pgbouncer tree
	mkdir $(FULL)
	(for f in $(DISTFILES); do echo $$f; done) | cpio -pm $(FULL)
	tar xf lib/*.tgz
	mv libusual-* $(FULL)/lib
	rm -f $(FULL)/lib/configure
	# tgz for pgbouncer
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
	rm -rf obj autom4te*

# clean autoconf results
realclean: distclean doc-realclean
	rm -f aclocal* include/config.h.in configure depcomp install-sh missing
	rm -f tags

# generate configure script and config.h.in
boot:
	aclocal -I lib/m4
	autoheader -f
	autoconf -f
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
$(builddir)/obj/%.s: $(srcdir)/src/%.c config.mak $(hdrs)
	@mkdir -p $(builddir)/obj
	$(E) "	CC -S" $<
	$(Q) $(CC) -S -fverbose-asm -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)
asms = $(objs:.o=.s)
asm: $(asms)

ifeq ($(PORTNAME),win32)

$(builddir)/obj/eventmsg.o: $(srcdir)/win32/eventmsg.rc
	$(E) "	WINDRES" $<
	$(Q) $(WINDRES) $< -o $@ --include-dir=$(srcdir)/win32

$(dlldef): $(dllobjs)
	$(E) "	DLLTOOL" $@
	$(Q) $(DLLTOOL) $(DEFFLAGS) --output-def $@ $(dllobjs)

# final executable
$(dll): $(builddir)/config.mak $(dllobjs) $(dlldef)
	$(E) "	DLLWRAP" $@
	$(Q) $(DLLWRAP) --def $(dlldef) -o $@ $(dllobjs)

zip = pgbouncer-$(PACKAGE_VERSION)-win32.zip

zip: all
	make -C doc html
ifeq ($(enable_debug),no)
	$(STRIP) pgbevent.dll
	$(STRIP) pgbouncer.exe
endif
	cp COPYRIGHT doc/COPYRIGHT.txt
	cp AUTHORS doc/AUTHORS.txt
	rm -f $(zip)
	zip $(zip) pgbouncer.exe pgbevent.dll doc/AUTHORS.txt doc/COPYRIGHT.txt doc/*.html

endif

stripped: $(exe) $(dll)
	$(STRIP) $(exe) $(dll)

tmp:
	@echo CPPFLAGS=$(CPPFLAGS)
	@echo USUAL_CPPFLAGS=$(USUAL_CPPFLAGS)
	@echo USUAL_LDFLAGS=$(USUAL_LDFLAGS)
