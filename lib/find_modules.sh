#! /bin/sh

set -e

top="$1"

# sanity check
test -n "$top" || {
  echo "usage: $0 USUAL_DIR SRC ..." >&2
  exit 1
}
test -f "$top/usual/base.h" || {
  echo "usage: $0 USUAL_DIR SRC ..." >&2
  exit 1
}

shift
test -n "$1" || exit 0

test -n "$AWK" || AWK=awk

# return uniq module names, exclude already found ones
grep_usual() {
  excl='excl["config"]=1'
  for m in $m_done; do
    excl="$excl;excl[\"$m\"]=1"
  done
  prog='
BEGIN { '"$excl"' }
/^#include[ \t]*[<"]usual\// {
  p1 = index($0, "/");
  p2 = index($0, ".");
  m = substr($0, p1+1, p2-p1-1);
  if (!excl[m]) print m;
}'
  $AWK "$prog" "$@" | sort -u
}

# return module filename globs
make_pats() {
  for m in "$@"; do
    echo "$top/usual/$m*.[ch]"
  done
}

# loop over grep until all mods are found
m_done=""
m_tocheck=`grep_usual "$@"`
while test -n "$m_tocheck"; do
  m_done="$m_done $m_tocheck"
  pats=`make_pats $m_tocheck`
  m_tocheck=`grep_usual $pats`
done

# done
echo $m_done
