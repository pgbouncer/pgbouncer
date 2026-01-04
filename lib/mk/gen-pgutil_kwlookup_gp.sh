#!/bin/sh

grep '^PG_KEYWORD' "$1" \
	| grep -v UNRESERVED \
	| sed 's/.*"\(.*\)",.*, *\(.*\)[)].*/\1/'
