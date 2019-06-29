-include ../config.mak

manpages = pgbouncer.1 pgbouncer.5

dist_man_MANS = $(manpages)

EXTRA_DIST = config.md usage.md Makefile $(manpages) \
	     frag-config-man.md frag-usage-man.md \
	     filter.py

CLEANFILES = pgbouncer_1.md pgbouncer_5.md

# make maintainer-clean removes those
MAINTAINERCLEANFILES = $(manpages)

SUBLOC = doc
abs_top_srcdir ?= $(CURDIR)/..
include $(abs_top_srcdir)/lib/mk/antimake.mk

PYTHON = python

pgbouncer.%: pgbouncer_%.md
	$(PANDOC) -s -t man -o $@ $<

pgbouncer_1.md: filter.py frag-usage-man.md usage.md
	$(PYTHON) $^ >$@

pgbouncer_5.md: filter.py frag-config-man.md config.md
	$(PYTHON) $^ >$@

.INTERMEDIATE: pgbouncer_1.md pgbouncer_5.md

web:
	make -C ../../pgbouncer.github.io
