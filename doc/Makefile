
wiki = https://developer.skype.com/SkypeGarage/DbProjects/PgBouncer
web = mkz@shell.pgfoundry.org:/home/pgfoundry.org/groups/pgbouncer/htdocs/

-include ../config.mak

MANPAGES = pgbouncer.1 pgbouncer.5
HTML = config.html usage.html todo.html

all: $(MANPAGES)

html: $(HTML)

install: $(MANPAGES)
	mkdir -p $(DESTDIR)$(mandir)/man1/
	mkdir -p $(DESTDIR)$(mandir)/man5/
	install -m 644 pgbouncer.1 $(DESTDIR)$(mandir)/man1/
	install -m 644 pgbouncer.5 $(DESTDIR)$(mandir)/man5/

upload:
	devupload.sh overview.txt $(wiki)
	#devupload.sh todo.txt $(wiki)/ToDo
	#devupload.sh usage.txt $(wiki)/UsageInfo
	#devupload.sh config.txt $(wiki)/ConfigFile

ifneq ($(XMLTO),)
pgbouncer.1: usage.xml
	xmlto man $<

pgbouncer.5: config.xml
	xmlto man $<
endif

ifneq ($(ASCIIDOC),)
%.xml: %.txt
	#asciidoc -b docbook -d manpage -o - $< > $@
	asciidoc -b docbook -d manpage -o - $< \
	| python fixman.py > $@

%.html: %.txt
	asciidoc -a toc $<
endif

clean:
	rm -f *.html *.xml

distclean: clean

realclean: distclean
	rm -f *.[1-9]

web: $(HTML)
	rsync -av $(HTML) $(web)/doc/

