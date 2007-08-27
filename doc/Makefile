
wiki = https://developer.skype.com/SkypeGarage/DbProjects/PgBouncer
web = mkz@shell.pgfoundry.org:/home/pgfoundry.org/groups/pgbouncer/htdocs/

all: man

man: pgbouncer.1 pgbouncer.5
html: pgbouncer.config.html pgbouncer.cmdline.html

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
	asciidoc -b docbook -d manpage $<

%.html: %.txt
	asciidoc $<

manpage.xml: manpage.txt
	asciidoc8 -d manpage -b docbook $<

clean:
	rm -f pgbouncer.8 manpage.xml *.[1-9] *.html *.xml

