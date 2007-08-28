
wiki = https://developer.skype.com/SkypeGarage/DbProjects/PgBouncer
web = mkz@shell.pgfoundry.org:/home/pgfoundry.org/groups/pgbouncer/htdocs/

-include ../config.mak

MANPAGES = pgbouncer.1 pgbouncer.5

all: $(MANPAGES)

html: pgbouncer.config.html pgbouncer.cmdline.html

install: $(MANPAGES)
	mkdir -p $(DESTDIR)$(mandir)/man1/
	mkdir -p $(DESTDIR)$(mandir)/man5/
	install -m 644 pgbouncer.1 $(DESTDIR)$(mandir)/man1/
	install -m 644 pgbouncer.5 $(DESTDIR)$(mandir)/man5/

upload:
	devupload.sh overview.txt $(wiki)
	devupload.sh todo.txt $(wiki)/ToDo
	devupload.sh usage.txt $(wiki)/UsageInfo
	devupload.sh config.txt $(wiki)/ConfigFile

pgbouncer.1: pgbouncer.cmdline.xml
	xmlto man $<

pgbouncer.5: pgbouncer.config.xml
	xmlto man $<

%.xml: %.txt
	asciidoc -b docbook -d manpage -o - $< \
	| python fixman.py > $@

%.html: %.txt
	asciidoc -a toc $<

manpage.xml: manpage.txt
	asciidoc8 -d manpage -b docbook $<

clean:
	rm -f pgbouncer.8 manpage.xml *.[1-9] *.html *.xml

realclean distclean: clean

