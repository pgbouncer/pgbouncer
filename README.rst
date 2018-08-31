
PgBouncer
=========

Lightweight connection pooler for PostgreSQL.

Homepage
    https://pgbouncer.github.io

Sources, bugtracking
    https://github.com/pgbouncer/pgbouncer

Building
---------

PgBouncer depends on few things to get compiled:

* `GNU Make`_ 3.81+
* libevent_ 2.0
* `pkg-config`_
* (optional) OpenSSL_ 1.0.1 for TLS support.
* (optional) `c-ares`_ as alternative to libevent's evdns.

.. _GNU Make: https://www.gnu.org/software/make/
.. _libevent: http://libevent.org/
.. _`pkg-config`: https://www.freedesktop.org/wiki/Software/pkg-config/
.. _OpenSSL: https://www.openssl.org/
.. _`c-ares`: http://c-ares.haxx.se/

When dependencies are installed just run::

    $ ./configure --prefix=/usr/local --with-libevent=libevent-prefix
    $ make
    $ make install

If you are building from Git, or are building for Windows, please see
separate build instructions below.

DNS lookup support
------------------

Starting from PgBouncer 1.4, it does hostname lookups at connect
time instead just once at config load time.  This requires proper
async DNS implementation.  Following list shows supported backends
and their probing order:

+----------------------------+----------+-----------+------------+----------------+---------------------------------------+
| backend                    | parallel | EDNS0 (1) | /etc/hosts | SOA lookup (2) | note                                  |
+============================+==========+===========+============+================+=======================================+
| c-ares                     | yes      | yes       | yes        | yes            | ipv6+CNAME buggy in <=1.10            |
+----------------------------+----------+-----------+------------+----------------+---------------------------------------+
| udns                       | yes      | yes       | no         | yes            | ipv4-only                             |
+----------------------------+----------+-----------+------------+----------------+---------------------------------------+
| evdns, libevent 2.x        | yes      | no        | yes        | no             | does not check /etc/hosts updates     |
+----------------------------+----------+-----------+------------+----------------+---------------------------------------+
| getaddrinfo_a, glibc 2.9+  | yes      | yes (3)   | yes        | no             | N/A on non-linux                      |
+----------------------------+----------+-----------+------------+----------------+---------------------------------------+
| getaddrinfo, libc          | no       | yes (3)   | yes        | no             | N/A on win32, requires pthreads       |
+----------------------------+----------+-----------+------------+----------------+---------------------------------------+
| evdns, libevent 1.x        | yes      | no        | no         | no             | buggy                                 |
+----------------------------+----------+-----------+------------+----------------+---------------------------------------+

1. EDNS0 is required to have more than 8 addresses behind one hostname.
2. SOA lookup is needed to re-check hostnames on zone serial change
3. To enable EDNS0, add `options edns0` to /etc/resolv.conf

`./configure` also has flags `--enable-evdns` and `--disable-evdns` which
turn off automatic probing and force use of either `evdns` or `getaddrinfo_a()`.

PAM authorization
-----------------

To enable PAM authorization `./configure` has a flag `--with-pam` (default value is no). When compiled with
PAM support new global authorization type `pam` appears which can be used to validate users through PAM.

Building from Git
-----------------

Building PgBouncer from Git requires that you fetch libusual
submodule and generate the header and config files before
you can run configure::

	$ git clone https://github.com/pgbouncer/pgbouncer.git
	$ cd pgbouncer
	$ git submodule init
	$ git submodule update
	$ ./autogen.sh
	$ ./configure ...
	$ make
	$ make install

Additional packages required: autoconf, automake, libtool, python-docutils

Building for WIN32
------------------

At the moment only build env tested is MINGW32 / MSYS.  Cygwin
and Visual $ANYTHING are untested.  Libevent 2.x is required
for DNS hostname lookup.

Then do the usual::

	$ ./configure ...
	$ make

If cross-compiling from Unix::

	$ ./configure --host=i586-mingw32msvc ...

Running on WIN32
----------------

Running from command-line goes as usual, except -d (daemonize),
-R (reboot) and -u (switch user) switches will not work.

To run pgbouncer as a Windows service, you need to configure
`service_name` parameter to set name for service.  Then::

	$ pgbouncer -regservice config.ini

To uninstall service::

	$ pgbouncer -unregservice config.ini

To use Windows Event Log, set "syslog = 1" in config file.
But before you need to register pgbevent.dll::

	$ regsvr32 pgbevent.dll

To unregister it, do::

        $ regsvr32 /u pgbevent.dll

Building with Docker
--------------------

Simply run::

        $ docker build -t pgbouncer .

You can then run it with the certain environment variables::

        $ docker run -d -e DB_HOST=pghost -e DB_USER=pguser \
                        -e DB_PASSWORD=pgpass \
                        pgbouncer

See the `entrypoint.sh` for more info

Or you can mount a config file::

        $ docker run -d -v pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini \
              pgbouncer
