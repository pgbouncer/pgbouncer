EXTRA_DIST = lib.sh newca.sh newsite.sh create_certs.sh test.ini Makefile

SUBLOC = test/ssl

include ../../config.mak
include ../../lib/mk/antimake.mk

check: all
	./test.sh
