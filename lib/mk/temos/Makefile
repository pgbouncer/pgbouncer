#
# This Makefile does not use Antimake because it must work
# even when Antimake is broken.
#

TEMOS = \
	antimake1 antimake2 antimake3 antimake4 antimake5 antimake6 \
	libusual1 libusual2 libusual3 libusual4 libusual5 libusual6 \



OUT = $(addsuffix .txt,$(addprefix output/, $(TEMOS)))
HTML = $(addsuffix .html,$(addprefix html/, $(TEMOS))) \
       html/index.html html/antimake.html

ExpFile = $(subst .temo,.txt,$(subst src/,expected/,$(1)))
OutFile = $(subst .temo,.txt,$(subst src/,output/,$(1)))

V ?= 0
ifeq ($(V),0)
E = @echo
Q = @
else
E = @true
Q =
endif

all: qtest

.PHONY: all test ack clean html

html: $(HTML)

am:
	rm -f html/anti*
	$(MAKE)

ftest: clean qtest
qtest: $(OUT)
	@diff -urN expected output > regressions.diff || { \
		cat regressions.diff; \
		echo "FAIL: Result does not match expected output"; \
		exit 1; \
	}
	$(Q) rm -f regressions.diff
	$(E) "All OK"

#../antimake.mk ../../m4/usual.m4
output/%.txt: src/%.temo libtemo.sh
	@mkdir -p output
	@printf "$< ... "
	@bash $< > $@ 2>&1 && { cmp -s $@ $(call ExpFile,$<) && echo ok || echo failed; } \
		|| { echo "$< failed:" ; tail $(call OutFile,$<); exit 1; }

html/%.html: output/%.txt
	@mkdir -p html
	asciidoc -o - $< | grep -v '^Last updated ' > $@

ack:
	cp output/*.txt expected/

clean:
	rm -rf tmp html output regressions.diff

html/index.html: index.txt
	@mkdir -p html
	asciidoc -o - $< | grep -v '^Last updated ' > $@

html/antimake.html: ../antimake.txt
	@mkdir -p html
	asciidoc -a toc -o - $< | grep -v '^Last updated ' > $@
