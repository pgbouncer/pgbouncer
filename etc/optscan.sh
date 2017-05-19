#! /bin/sh

# Check if all options in main.c are defined in sample ini and docs

sources="src/main.c"
targets="doc/config.rst etc/pgbouncer.ini"

for opt in `grep CF_ABS "$sources" | sed -r 's/^[^"]*"([^"]*)".*/\1/'`; do
  for conf in $targets; do
    if ! grep -q "$opt" "$conf"; then
      echo "$opt is missing in $conf"
    fi
  done
done


