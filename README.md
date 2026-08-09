PgBouncer
=========

Lightweight connection pooler for PostgreSQL.

Homepage: <https://www.pgbouncer.org/>

Sources, bug tracking: <https://github.com/pgbouncer/pgbouncer>

Building
---------

PgBouncer can be built with either [Meson] (recommended) or the older
Autoconf-based build system.  Both are supported for now; the Autoconf build
will eventually be removed.  Compilation depends on a few things:

* [Libevent] 2.0+
* [pkg-config]
* [OpenSSL] 1.0.1+ for TLS support
* a C11-capable C compiler
* (optional) [c-ares] as alternative to Libevent's evdns
* (optional) LDAP libraries
* (optional) PAM libraries

The Meson build additionally needs [Meson] 0.58+ and [Ninja]; the Autoconf
build needs [GNU Make] 3.81+.

[Meson]: https://mesonbuild.com/
[Ninja]: https://ninja-build.org/
[GNU Make]: https://www.gnu.org/software/make/
[Libevent]: http://libevent.org/
[pkg-config]: https://www.freedesktop.org/wiki/Software/pkg-config/
[OpenSSL]: https://www.openssl.org/
[c-ares]: http://c-ares.haxx.se/

When dependencies are installed, build with Meson:

    $ meson setup build --prefix=/usr/local
    $ meson compile -C build
    $ meson install -C build

or with Autoconf:

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
with `-Dcares=enabled` (configure: `--with-cares`) or disabled with
`-Dcares=disabled` (configure: `--without-cares`).  If c-ares is not used
(not found or disabled), then Libevent is used.  Specify `-Devdns=false`
(configure: `--disable-evdns`) to disable the use of Libevent's evdns and
fall back to a libc-based implementation.

Optional features
-----------------

The PAM, LDAP and systemd features are auto-detected by meson: their `-Dpam`,
`-Dldap` and `-Dsystemd` options default to `auto`, so each is built when its
libraries are present.  Force one on with `-D<feature>=enabled` or off with
`-D<feature>=disabled`.  The Autoconf build does not auto-detect them; opt in
explicitly with `--with-pam`, `--with-ldap` or `--with-systemd`.

PAM authentication
------------------

When compiled with PAM support, a new global authentication type `pam` is
available to validate users through PAM.

LDAP authentication
------------------

When compiled with LDAP support, a new global authentication type `ldap` is
available to validate users through LDAP.

systemd integration
-------------------

systemd support allows using `Type=notify` (or `Type=notify-reload` if you are
using systemd 253 or later) as well as socket activation.  See
`etc/pgbouncer.service` and `etc/pgbouncer.socket` for examples.

Building from Git
-----------------

With Meson you can build straight from a checkout; pandoc is required to
build the man pages:

	$ git clone https://github.com/pgbouncer/pgbouncer.git
	$ cd pgbouncer
	$ meson setup build
	$ meson compile -C build
	$ meson install -C build

Run `meson configure build` to list the available `-D` options.

The Autoconf build instead requires that you generate the header and
configuration files before you can run `configure`:

	$ ./autogen.sh
	$ ./configure
	$ make
	$ make install

All files will be installed under `/usr/local` by default. You can
supply one or more command-line options to `configure`. Run
`./configure --help` to list the available options and the environment
variables that customizes the configuration.

Additional packages required for the Autoconf build from Git: autoconf,
automake, libtool, pandoc

Testing
-------

See the [`README.md` file in the test directory][1] on how to run the tests.

[1]: https://github.com/pgbouncer/pgbouncer/blob/master/test/README.md

Building on Windows
-------------------

The only supported build environment on Windows is MinGW.  Cygwin and
Visual $ANYTHING are not supported.

To build on MinGW, do the usual Meson build:

	$ meson setup build
	$ meson compile -C build

or the Autoconf build:

	$ ./configure
	$ make

If cross-compiling from Unix with Autoconf:

	$ ./configure --host=i586-mingw32msvc

The LDAP build option is currently not supported on Windows.

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
