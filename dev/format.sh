#!/bin/sh
#
# Formatting and linting for pgbouncer, independent of the build system.
#
# Usage:
#   dev/format.sh check       verify C and Python formatting + import order (CI)
#   dev/format.sh fix         reformat C and Python in place
#   dev/format.sh fix-c       reformat only C in place
#   dev/format.sh fix-python  reformat only Python in place
#   dev/format.sh lint        run only the ruff linter
#
# C code is formatted with a pinned uncrustify that is built from source on
# first use and cached as ./uncrustify in the repo root; CI caches that file
# keyed on UNCRUSTIFY_VERSION so it is only rebuilt when the version is bumped.
# Python formatting, import sorting and linting are all handled by ruff.
#
# This replaces the format/format-check/lint/uncrustify targets that used to
# live in the autoconf Makefile.

set -eu

UNCRUSTIFY_VERSION=0.77.1

# Run from the repo root regardless of where the script was invoked from, so the
# globs and the cached ./uncrustify path resolve consistently.
cd "$(git rev-parse --show-toplevel)"

UNCRUSTIFY=./uncrustify

# The set of C sources and headers uncrustify is responsible for. Kept in sync
# with the UNCRUSTIFY_FILES list that the Makefile used.
uncrustify_globs='
	include/*.h src/*.c test/*.c
	lib/test/*.c lib/usual/*.c lib/usual/crypto/*.c lib/usual/hashing/*.c lib/usual/tls/*.c
	lib/test/*.h lib/usual/*.h lib/usual/crypto/*.h lib/usual/hashing/*.h lib/usual/tls/*.h
'

# Build the pinned uncrustify unless the cached binary is already present.
ensure_uncrustify() {
	if [ -x "$UNCRUSTIFY" ]; then
		return
	fi

	echo "Building uncrustify $UNCRUSTIFY_VERSION ..."
	root=$(pwd)
	tmp=$(mktemp -d)
	# shellcheck disable=SC2064
	trap "rm -rf '$tmp'" EXIT

	tarball="uncrustify-$UNCRUSTIFY_VERSION.tar.gz"
	curl -L \
		"https://github.com/uncrustify/uncrustify/archive/refs/tags/$tarball" \
		--output "$tmp/$tarball"
	tar xzf "$tmp/$tarball" -C "$tmp"
	cmake -S "$tmp/uncrustify-uncrustify-$UNCRUSTIFY_VERSION" -B "$tmp/build"
	cmake --build "$tmp/build"
	cp "$tmp/build/uncrustify" "$root/uncrustify"
}

do_check() {
	ensure_uncrustify
	# Reject trailing whitespace / other whitespace errors across the tree.
	git diff-tree --check "$(git hash-object -t tree /dev/null)" HEAD
	ruff format --check --diff
	ruff check --select I --diff
	# shellcheck disable=SC2086
	"$UNCRUSTIFY" -c uncrustify.cfg --check -L WARN $uncrustify_globs
}

do_fix_c() {
	ensure_uncrustify
	# shellcheck disable=SC2086
	"$UNCRUSTIFY" -c uncrustify.cfg --replace --no-backup -L WARN $uncrustify_globs
}

do_fix_python() {
	ruff format
	ruff check --select I --fix
}

do_fix() {
	do_fix_c
	do_fix_python
}

do_lint() {
	ruff check
}

case "${1:-}" in
	check) do_check ;;
	fix) do_fix ;;
	fix-c) do_fix_c ;;
	fix-python) do_fix_python ;;
	lint) do_lint ;;
	*)
		echo "usage: $0 {check|fix|fix-c|fix-python|lint}" >&2
		exit 2
		;;
esac
