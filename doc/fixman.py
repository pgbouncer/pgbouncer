#! /usr/bin/env python
import sys,re
# add empty <simpara> after <literallayout> to force line break
sys.stdout.write(re.sub(r"</literallayout>\s+<simpara>", r"\g<0></simpara><simpara>", sys.stdin.read()))
