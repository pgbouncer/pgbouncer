
# sources
SRCS = client.c loader.c objects.c pooler.c proto.c sbuf.c server.c util.c \
       admin.c stats.c takeover.c md5.c janitor.c pktbuf.c system.c main.c \
       varcache.c
HDRS = client.h loader.h objects.h pooler.h proto.h sbuf.h server.h util.h \
       admin.h stats.h takeover.h md5.h janitor.h pktbuf.h system.h bouncer.h \
       list.h mbuf.h varcache.h

# data & dirs to include in tgz
DOCS = doc/makefile doc/overview.txt doc/pgbouncer.cmdline.txt \
       doc/pgbouncer.config.txt doc/todo.txt
MANPAGES = doc/pgbouncer.1 doc/pgbouncer.5
DATA = README NEWS AUTHORS etc/pgbouncer.ini Makefile config.mak.in config.h.in \
       configure configure.ac debian/packages debian/changelog doc/Makefile
DIRS = doc etc src debian

# keep autoconf stuff separate
-include config.mak

ifeq ($(enable_debug),yes)
CFLAGS += -DDBGVER="\"compiled by <$${USER}@`hostname`> at `date '+%Y-%m-%d %H:%M:%S'`\""
endif

# calculate full-path values
OBJS = $(SRCS:.c=.o)
hdrs = $(addprefix $(srcdir)/src/, $(HDRS))
srcs = $(addprefix $(srcdir)/src/, $(SRCS))
objs = $(addprefix $(builddir)/lib/, $(OBJS))
FULL = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
DISTFILES = $(DIRS) $(DATA) $(DOCS) $(srcs) $(hdrs) $(MANPAGES)

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
all: pgbouncer doc-all

# final executable
pgbouncer: config.mak $(objs)
	$(E) "	LD" $@
	$(Q) $(CC) -o $@ $(LDFLAGS) $(objs) $(LIBS)

# objects depend on all the headers
$(builddir)/lib/%.o: $(srcdir)/src/%.c config.mak $(hdrs)
	@mkdir -p $(builddir)/lib
	$(E) "	CC" $<
	$(Q) $(CC) -c -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)

# install binary and other stuff
install: pgbouncer doc-install
	mkdir -p $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(docdir)
	$(BININSTALL) -m 755 pgbouncer $(DESTDIR)$(bindir)
	$(INSTALL) -m 644 $(srcdir)/etc/pgbouncer.ini  $(DESTDIR)$(docdir)

# create tarfile
tgz: config.mak $(DISTFILES) $(MANPAGES)
	rm -rf $(FULL) $(FULL).tgz
	mkdir $(FULL)
	(for f in $(DISTFILES); do echo $$f; done) | cpio -p $(FULL)
	tar czf $(FULL).tgz $(FULL)
	rm -rf $(FULL)

doc/pgbouncer.1:
	make -C doc pgbouncer.1

doc/pgbouncer.5:
	make -C doc pgbouncer.5

# create debian package
deb: configure
	yada rebuild
	debuild -uc -us -b

# clean object files
clean: doc-clean
	rm -f *~ src/*~ *.o src/*.o lib/*.o lib/*.s pgbouncer core core.*
	rm -f lib/*.log

# clean configure results
distclean: clean doc-distclean
	rm -f config.h config.log config.status config.mak
	rm -rf lib autom4te*

# clean autoconf results
realclean: distclean
	rm -f aclocal* config.h.in configure depcomp install-sh missing
	rm -f tags

# generate configure script and config.h.in
boot: distclean
	autoreconf -i -f
	rm -rf autom4te* config.h.in~

# targets can depend on this to force ./configure
config.mak::
	@test -f configure || { \
		 echo "Please run 'make boot && ./configure' first.";exit 1;}
	@test -f $@ || { echo "Please run ./configure first.";exit 1;}

doc-all doc-install doc-clean doc-distclean doc-realclean:
	$(MAKE) -C doc $(subst doc-,,$@) DESTDIR=$(DESTDIR)


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

# fixes for macos
SPARSE_MACOS=-D__STDC_VERSION__=199901 -D__LP64__=0 -DSENDFILE=1 \
		-I/usr/lib/gcc/i486-linux-gnu/4.1.2/include
# sparse does not have any identity
SPARCE_FLAGS=-D__LITTLE_ENDIAN__ -D__i386__ -D__GNUC__=3 -D__GNUC_MINOR__=0 \
		-Wno-transparent-union \
		-Wall $(SPARSE_MACOS) $(CPPFLAGS) $(DEFS)

# run sparse over code
check: config.mak
	$(E) "	CHECK" $(srcs)
	$(Q) sparse $(SPARCE_FLAGS) $(srcs)

pgbouncer.pg:
	$(CC) -pg $(DEFS) -g -O2 $(CPPFLAGS) $(LDFLAGS) -o $@ $(srcs) $(LIBS)

pg: pgbouncer.pg

$(builddir)/lib/%.s: $(srcdir)/src/%.c config.mak $(hdrs)
	@mkdir -p $(builddir)/lib
	$(E) "	CC -S" $<
	$(Q) $(CC) -S -o $@ $< $(DEFS) $(CFLAGS) $(CPPFLAGS)
asms = $(objs:.o=.s)
asm: $(asms)

