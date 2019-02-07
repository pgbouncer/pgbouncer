-include ../config.mak

manpages = pgbouncer.1 pgbouncer.5

dist_man_MANS = $(manpages)

EXTRA_DIST = config.md usage.md Makefile $(manpages) \
	     frag-config-man.md frag-usage-man.md

# make maintainer-clean removes those
MAINTAINERCLEANFILES = $(manpages)

SUBLOC = doc
abs_top_srcdir ?= $(CURDIR)/..
include $(abs_top_srcdir)/lib/mk/antimake.mk


pgbouncer.1: frag-usage-man.md usage.md
	$(PANDOC) --lua-filter=filter.lua -s -t man -o $@ $^

pgbouncer.5: frag-config-man.md config.md
	$(PANDOC) --lua-filter=filter.lua -s -t man -o $@ $^

web:
	make -C ../../pgbouncer.github.io
