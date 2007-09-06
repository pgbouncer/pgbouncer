#! /usr/bin/env python

import sys,re

# hacks to force empty lines into manpage
ln1 = r"\1<simpara></simpara>\2"
xml = sys.stdin.read()
xml = re.sub(r"(</literallayout>\s*)(<simpara)", ln1, xml)
xml = re.sub(r"(</variablelist>\s*)(<simpara)", ln1, xml)
sys.stdout.write(xml)

