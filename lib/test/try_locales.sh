#! /bin/sh

make -C .. && make all regtest_compat

echo ""
echo "# regtest_compat, no locale"
./regtest_compat --quiet
echo "# regtest_system, no locale"
./regtest_system --quiet

export USE_LOCALE=1

lclist="en_US.UTF-8 ru_RU.UTF-8 et_EE.UTF-8 fa_IR.UTF-8 ps_AF.UTF-8 aa_ER.UTF-8 ja_JP.UTF-8"
lclist="$lclist et_EE.ISO-8859-1 ru_RU.koi-8r ja_JP.EUC-JP zh_CN.BIG5"

for lc in $lclist; do
  if locale -a | grep -i "`echo $lc|sed 's/-//g'`" > /dev/null; then
    LC_ALL=$lc
    export LC_ALL
    echo "# regtest_compat, LC_ALL=$LC_ALL"
    ./regtest_compat --quiet
    echo "# regtest_system, LC_ALL=$LC_ALL"
    ./regtest_system --quiet
  else
    echo "### $lc not available ###"
  fi
done
