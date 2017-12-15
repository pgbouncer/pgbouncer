-include ../config.mak

manpages = pgbouncer.1 pgbouncer.5

dist_man_MANS = $(manpages)

EXTRA_DIST = config.rst usage.rst Makefile $(manpages) \
	     frag-config-man frag-usage-man

# make maintainer-clean removes those
MAINTAINERCLEANFILES = $(manpages)

SUBLOC = doc
abs_top_srcdir ?= $(CURDIR)/..
include $(abs_top_srcdir)/lib/mk/antimake.mk


pgbouncer.1: usage.rst frag-usage-man
	$(SED) -e '4r frag-usage-man' usage.rst | $(RST2MAN) --exit-status=2 > $@

pgbouncer.5: config.rst frag-config-man
	$(SED) -e '4r frag-config-man' config.rst | $(RST2MAN) --exit-status=2 > $@

web:
	make -C ../../pgbouncer.github.io

