#! /bin/sh

rxtest=./testregex.libc
rxtest=./testregex.usual

tests="basic.dat categorize.dat nullsubexpr.dat"
tests="$tests rightassoc.dat"
#tests="$tests leftassoc.dat"
tests="$tests forcedassoc.dat"
tests="$tests repetition.dat"
tests="$tests interpretation.dat"

for t in $tests; do
  printf "%-20s" "$t"
  #$rxtest < data/$t | grep -vE '(NOTE|Research)'
  $rxtest < data/$t | tail -n +4 | grep -vE 'haskell|mimi|NOTE'
done

#$rxtest < data/categorize.dat | tail -n +4
