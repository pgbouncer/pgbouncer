#! /bin/sh

# test find_modules.sh vs. various awks

# random awks that may be around
awk_list="mawk gawk nawk oawk"
awk_list="$awk_list heirloom-nawk heirloom-oawk"
awk_list="$awk_list original-awk plan9-awk"

fmod=../find_modules.sh
dir=fmod_test
usual_dir=..

rm -rf $dir
mkdir $dir

ok=1
for f in *.c; do
  printf "$f .. "

  # write reference with default 'awk'
  ref=$dir/$f.awk
  $fmod $usual_dir $f > $ref 2>&1

  for a in $awk_list; do
    which $a > /dev/null || continue
    printf "$a "
    out=$dir/$f.$a
    AWK=$a \
    $fmod $usual_dir $f > $out 2>&1
    cmp -s $ref $out || {
      printf "(FAIL) "
      ok=0
    }
  done
  echo ""
done

if test $ok = 1; then
  echo "All OK"
else
  echo "FAIL: not all tests passed"
  exit 1
fi
