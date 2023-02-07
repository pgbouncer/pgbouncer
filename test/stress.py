#! /usr/bin/env python3

import random
import threading
import time

import psycopg2

n_thread = 100
longtx = False
tx_sleep = 8

conn_data = {
    "dbname": "marko",
    #'host': '127.0.0.1',
    "host": "/tmp",
    "port": "6432",
    "user": "marko",
    #'password': '',
    "connect_timeout": "5",
}


def get_connstr():
    tmp = []
    for k, v in conn_data.items():
        tmp.append(k + "=" + v)
    return " ".join(tmp)


class WorkThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.stat_lock = threading.Lock()
        self.query_cnt = 0

    def inc_cnt(self):
        self.stat_lock.acquire()
        self.query_cnt += 1
        self.stat_lock.release()

    def fetch_cnt(self):
        self.stat_lock.acquire()
        val = self.query_cnt
        self.query_cnt = 0
        self.stat_lock.release()
        return val

    def run(self):
        try:
            time.sleep(random.random() * 10.0)
        except Exception:
            pass
        while 1:
            try:
                self.main_loop()
            except KeyboardInterrupt:
                break
            except SystemExit:
                break
            except Exception as d:
                print(d)
                try:
                    time.sleep(5)
                except Exception:
                    pass

    def main_loop(self):
        db = psycopg2.connect(get_connstr())
        if not longtx:
            db.autocommit = True
        n = 0
        while n < 10:
            self.do_work(db)
            self.inc_cnt()
            n += 1

    def do_work(self, db):
        curs = db.cursor()
        q = "select pg_sleep(%.02f)" % (random.random() * 1)
        curs.execute(q)
        time.sleep(tx_sleep * random.random() + 1)
        if longtx:
            db.commit()


def main():
    print("connstr %s" % get_connstr())

    thread_list = []
    while len(thread_list) < n_thread:
        t = WorkThread()
        t.start()
        thread_list.append(t)

    print("started %d threads" % len(thread_list))

    last = time.time()
    while 1:
        time.sleep(1)
        now = time.time()
        dur = now - last
        if dur >= 5:
            last = now
            cnt = 0
            for t in thread_list:
                cnt += t.fetch_cnt()
            avg = cnt / dur
            print("avg %s" % avg)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        pass
    except KeyboardInterrupt:
        pass
    # except Exception as d:
    #    print d
