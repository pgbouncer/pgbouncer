#! /bin/sh

set -e

test -f test_common.h || {
  echo "wrong dir"
  exit 1
}

cd ..

rm -rf .objs test/.objs
rm -rf test/lcov/*

make -C test test_config.h
make -f test/coverage.mk CC="gcc -fprofile-arcs -ftest-coverage" CFLAGS="-O0 -g"

./covtest || true

echo 'Running lcov'
lcov -q --capture --directory .objs/covtest -b . --output-file coverage.info.tmp

echo 'Fixing filenames'
sed -e '/SF:/s,/\./,/,' coverage.info.tmp > coverage.info

echo 'Running genhtml'
genhtml -q coverage.info --output-directory test/lcov
echo 'Result: test/lcov/index.html'
rm -f coverage.info.tmp coverage.info
rm -f covtest
rm -rf .objs/covtest
