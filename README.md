PgBouncer
=========

Lightweight connection pooler for PostgreSQL.

Homepage: <https://www.pgbouncer.org/>

Sources, bug tracking: <https://github.com/pgbouncer/pgbouncer>

Building
---------

PgBouncer depends on few things to get compiled:

* [GNU Make] 3.81+
* [Libevent] 2.0+
* [pkg-config]
* [OpenSSL] 1.0.1+ for TLS support
* (optional) [c-ares] as alternative to Libevent's evdns
* (optional) PAM libraries
* (optional) LDAP libraries

[GNU Make]: https://www.gnu.org/software/make/
[Libevent]: http://libevent.org/
[pkg-config]: https://www.freedesktop.org/wiki/Software/pkg-config/
[OpenSSL]: https://www.openssl.org/
[c-ares]: http://c-ares.haxx.se/

When dependencies are installed just run:

    $ ./configure --prefix=/usr/local
    $ make
    $ make install

If you are building from Git, or are building for Windows, please see
separate build instructions below.

DNS lookup support
------------------

PgBouncer does host name lookups at connect time instead of just once
at configuration load time.  This requires an asynchronous DNS
implementation.  The following table shows supported backends and
their probing order:

| backend                    | parallel | EDNS0 (1) | /etc/hosts | SOA lookup (2) | note                                  |
|----------------------------|----------|-----------|------------|----------------|---------------------------------------|
| c-ares                     | yes      | yes       | yes        | yes            | IPv6+CNAME buggy in <=1.10            |
| evdns, libevent 2.x        | yes      | no        | yes        | no             | does not check /etc/hosts updates     |
| getaddrinfo_a, glibc 2.9+  | yes      | yes (3)   | yes        | no             | N/A on non-glibc                      |
| getaddrinfo, libc          | no       | yes (3)   | yes        | no             | requires pthreads                     |

1. EDNS0 is required to have more than 8 addresses behind one host name.
2. SOA lookup is needed to re-check host names on zone serial change.
3. To enable EDNS0, add `options edns0` to `/etc/resolv.conf`.

c-ares is the most fully-featured implementation and is recommended
for most uses and binary packaging (if a sufficiently new version is
available).  Libevent's built-in evdns is also suitable for many uses,
with the listed restrictions.  The other backends are mostly legacy
options at this point and don't receive much testing anymore.

By default, c-ares is used if it can be found.  Its use can be forced
with `configure --with-cares` or disabled with `--without-cares`.  If
c-ares is not used (not found or disabled), then Libevent is used.  Specify
`--disable-evdns` to disable the use of Libevent's evdns and fall back to a
libc-based implementation.

PAM authentication
------------------

To enable PAM authentication, `./configure` has a flag `--with-pam`
(default value is no).  When compiled with PAM support, a new global
authentication type `pam` is available to validate users through PAM.

LDAP authentication
------------------

To enable LDAP authentication, `./configure` has a flag `--with-ldap`
(default value is no).  When compiled with LDAP support, a new global
authentication type `ldap` is available to validate users through LDAP.

systemd integration
-------------------

To enable systemd integration, use the `configure` option
`--with-systemd`.  This allows using `Type=notify` (or `Type=notify-reload` if
you are using systemd 253 or later) as well as socket activation.  See
`etc/pgbouncer.service` and `etc/pgbouncer.socket` for examples.

Building from Git
-----------------

Building PgBouncer from Git requires that you generate the header and
configuration files before you can run `configure`:

	$ git clone https://github.com/pgbouncer/pgbouncer.git
	$ cd pgbouncer
	$ ./autogen.sh
	$ ./configure
	$ make
	$ make install

All files will be installed under `/usr/local` by default. You can
supply one or more command-line options to `configure`. Run
`./configure --help` to list the available options and the environment
variables that customizes the configuration.

Additional packages required: autoconf, automake, libtool, pandoc

Testing
-------

See the [`README.md` file in the test directory][1] on how to run the tests.

[1]: https://github.com/pgbouncer/pgbouncer/blob/master/test/README.md

Building on Windows
-------------------

The only supported build environment on Windows is MinGW.  Cygwin and
Visual $ANYTHING are not supported.

To build on MinGW, do the usual:

	$ ./configure
	$ make

If cross-compiling from Unix:

	$ ./configure --host=i586-mingw32msvc

Running on Windows
------------------

Running from the command line goes as usual, except that the `-d` (daemonize),
`-R` (reboot), and `-u` (switch user) switches will not work.

To run PgBouncer as a Windows service, you need to configure the
`service_name` parameter to set a name for the service.  Then:

	$ pgbouncer -regservice config.ini

To uninstall the service:

	$ pgbouncer -unregservice config.ini

To use the Windows event log, set `syslog = 1` in the configuration file.
But before that, you need to register `pgbevent.dll`:

	$ regsvr32 pgbevent.dll

To unregister it, do:

	$ regsvr32 /u pgbevent.dll
