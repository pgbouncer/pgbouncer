#!/usr/bin/env python3

import fileinput
import os
import sys

for line in fileinput.input():
    # substitute package version
    if line.startswith("% "):
        line = line.replace("@PACKAGE_VERSION@", os.environ["PACKAGE_VERSION"])
    # drop level-1 header
    if line.startswith("# "):
        continue
    # decrease level of all headers by 1
    if line.startswith("##"):
        line = line.replace("#", "", 1)
    # convert level-1 headers to uppercase
    if line.startswith("# "):
        line = line.upper()
    sys.stdout.write(line)
