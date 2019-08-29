EXTRA_DIST = lib.sh newca.sh newsite.sh test.ini test.sh Makefile

SUBLOC = test/ssl

include ../../config.mak
include ../../lib/mk/antimake.mk

check: all
	./test.sh
