#!/bin/sh

gperf -m5 "$1" \
	| sed '/^#line/d'
