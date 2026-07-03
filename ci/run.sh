#!/bin/sh
#
# Drive a build/test/install/dist step for either build system, so CI can
# exercise both meson and autoconf on every platform from one place.
#
# Usage: ci/run.sh <build|test|install|dist> <meson|autoconf>
#
# Env:
#   MESON_ARGS      extra `meson setup` options      (build, meson only)
#   CONFIGURE_ARGS  extra `./configure` options      (build, autoconf only)
#   PREFIX          install prefix (default: $HOME/install)
#   SCANBUILD       optional command prefix, e.g. "scan-build"
#   MAKE_JOBS       make/ninja parallelism (default: 4)
#   CONCURRENCY     pytest workers for autoconf `make check` (default: 4)
#
# --werror is passed for every build; everything else that differs per job
# (cassert, systemd, feature toggles, ...) comes in via MESON_ARGS/CONFIGURE_ARGS.
set -eu

action=${1:?usage: ci/run.sh <build|test|install|dist> <meson|autoconf>}
bs=${2:?usage: ci/run.sh <build|test|install|dist> <meson|autoconf>}

prefix=${PREFIX:-$HOME/install}
scanbuild=${SCANBUILD:-}
jobs=${MAKE_JOBS:-4}

case "$bs" in
meson | autoconf) ;;
*) echo "unknown build system: $bs" >&2; exit 2 ;;
esac

case "$action.$bs" in
build.meson)
	# shellcheck disable=SC2086
	$scanbuild meson setup build --prefix="$prefix" --werror ${MESON_ARGS:-}
	$scanbuild meson compile -C build -v
	;;
build.autoconf)
	./autogen.sh
	# shellcheck disable=SC2086
	$scanbuild ./configure --prefix="$prefix" --enable-werror ${CONFIGURE_ARGS:-}
	$scanbuild make -j"$jobs"
	;;
test.meson)
	meson test -C build -v --print-errorlogs
	;;
test.autoconf)
	make -j"$jobs" check CONCURRENCY="${CONCURRENCY:-4}"
	;;
install.meson)
	meson install -C build
	;;
install.autoconf)
	make -j"$jobs" install
	;;
dist.meson)
	# gztar to match the artifact glob (meson defaults to xztar).
	meson dist -C build --no-tests --formats gztar
	mkdir -p dist && cp build/meson-dist/pgbouncer-*.tar.gz dist/
	;;
dist.autoconf)
	make dist
	mkdir -p dist && cp pgbouncer-*.tar.gz dist/
	;;
*)
	echo "usage: ci/run.sh <build|test|install|dist> <meson|autoconf>" >&2
	exit 2
	;;
esac
