LANG=C
LC_ALL=C
export LANG LC_ALL

PATH=`pwd`/bin:$PATH
export PATH

set -e
set -o pipefail

SH="bash"

unset MAKELEVEL MAKEFLAGS
export MAKELEVEL MAKEFLAGS

code=0

# we want to test local commits
real_repo=../../..

# but final html should have fixed public url
show_repo=git://github.com/libusual/libusual.git

usual_clone() {
  enter_code
  echo "$ git clone $show_repo" "$@"
  git clone $real_repo "$@"
}

test_start() {
  rm -rf tmp
  mkdir tmp
  cd tmp
}

enter_code() {
  if test "$code" = "0"; then
    echo "---------------------------------"
    code=1
  fi
}

leave_code() {
  if test "$code" = "1"; then
    echo "---------------------------------"
    code=0
  fi
}

ls() {
  /bin/ls -C "$@"
}

title() {
  leave_code
  echo ""
  echo "=" "$@" "="
  echo ""
}

title2() {
  leave_code
  echo ""
  echo "==" "$@" "=="
  echo ""
}

title3() {
  leave_code
  echo ""
  echo "===" "$@" "==="
  echo ""
}

run() {
  enter_code
  echo "$ $*"
  case "$1" in
  cd|ls|export) $* ;;
  *) $SH -c "$*" 2>&1
  esac
}

runq() {
  enter_code
  echo "$ $*"
  echo "[...]"
  $SH -c "$*" > quiet.log 2>&1 || { tail -5 quiet.log; exit 1; }
  rm -f quiet.log
}

msg() {
  leave_code
  echo ""
  echo "$@"
  echo ""
}

longmsg() {
  leave_code
  echo ""
  sed 's/^	//'
  echo ""
}

cat_file() {
  leave_code
  mkdir -p `dirname $1`
  echo ".File: $1"
  case "$1" in
    *Makefile) echo "[source,makefile]" ;;
    *.[ch]) echo "[source,c]" ;;
    *.ac) echo "[source,autoconf]" ;;
    *.sh) echo "[source,shell]" ;;
  esac
  echo "-----------------------------------"
  sed 's/^	//' > $1
  cat $1
  echo "-----------------------------------"
}
