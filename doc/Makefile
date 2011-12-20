-include ../config.mak

web = pgf:/home/pgfoundry.org/groups/pgbouncer/htdocs/

manpages = pgbouncer.1 pgbouncer.5

EXTRA_DIST = config.txt usage.txt todo.txt faq.txt Makefile $(manpages)

ifeq ($(ASCIIDOC),)
ifneq ($(wildcard pgbouncer.[15]),)
# no asciidoc, but we have manpages
dist_man_MANS = $(manpages)
endif
else
# we have asciidoc, build everything
man_MANS = $(manpages)
doc_DATA = config.html usage.html todo.html faq.html README.html
endif

SUBLOC = doc
abs_top_srcdir ?= $(CURDIR)/..
include $(abs_top_srcdir)/lib/mk/antimake.mk

# add rules only if asciidoc is defined
ifneq ($(ASCIIDOC),)

pgbouncer.1: usage.xml
	$(XMLTO) man $<

pgbouncer.5: config.xml
	$(XMLTO) man $<

%.xml: %.txt
	$(ASCIIDOC) -b docbook -d manpage -o $@ $<

%.html: %.txt
	$(ASCIIDOC) -a toc -o $@ $<

README.html: ../README
	$(ASCIIDOC) -a toc -o $@ $<

web: $(doc_DATA)
	rsync -av $(doc_DATA) $(web)/doc/

endif # ASCIIDOC

