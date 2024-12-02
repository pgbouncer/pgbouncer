#! /bin/sh

# Check if all options in main.c are defined in sample ini and docs

sources="src/main.c"
targets="doc/config.md etc/pgbouncer.ini"

status=0

for opt in `grep CF_ABS "$sources" | sed -r 's/^[^"]*"([^"]*)".*/\1/'`; do
  for conf in $targets; do
    if ! grep -q "$opt" "$conf"; then
      echo "$opt is missing in $conf" 1>&2
      status=1
    fi
  done
done

exit $status
