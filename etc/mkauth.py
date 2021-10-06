#! /usr/bin/env python3

import sys
import os
import tempfile
import psycopg2

if len(sys.argv) != 3:
    print('usage: mkauth DSTFN CONNSTR')
    sys.exit(1)

# read old file
fn = sys.argv[1]
try:
    old = open(fn, 'r').read()
except IOError:
    old = ''

# create new file data
db = psycopg2.connect(sys.argv[2])
curs = db.cursor()
curs.execute("select usename, passwd from pg_shadow order by 1")
lines = []
for user, psw in curs.fetchall():
    user = user.replace('"', '""')
    if not psw:
        psw = ''
    psw = psw.replace('"', '""')
    lines.append('"%s" "%s" ""\n' % (user, psw))
db.commit()
cur = "".join(lines)

# if changed, replace data securely
if old != cur:
    fd, tmpfn = tempfile.mkstemp(dir=os.path.split(fn)[0])
    f = os.fdopen(fd, 'w')
    f.write(cur)
    f.close()
    os.rename(tmpfn, fn)
