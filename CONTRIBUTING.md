# Contributing to PgBouncer

Contributions are welcome! If you find a bug or have a feature
request, please open an issue or submit a pull request.

## Reporting bugs

To report a bug, open an issue in the GitHub issue tracker. Please
include:

* the PgBouncer version (`pgbouncer --version`) and how you installed it
* the operating system and the PostgreSQL server version
* the relevant parts of your `pgbouncer.ini` (remove passwords)
* the relevant log output
* steps to reproduce, what you expected, and what happened instead

**Do not report security vulnerabilities in public issues.** Use GitHub's
private vulnerability reporting under
<https://github.com/pgbouncer/pgbouncer/security/advisories>.

## Proposing changes

To propose changes, such as bug fixes, new features, documentation and
test changes, open a pull request. A maintainer will review the pull
request and either request changes or merge it. You can also comment
on others' open pull requests to give feedback and support the
maintainers.

See [README.md](README.md) for build instructions.

All change proposals should include tests and appropriate
documentation updates. You should run the test suite as you develop
locally (see [test/README.md](test/README.md)).

Run `make format`/`meson compile -C build format` to format the code,
`make format-check`/`meson compile -C build format-check` to check the
formatting, and `make lint`/`meson compile -C build lint` to run
linting checks on the code.

Pull requests are automatically checked that they build, pass the test
suite and follow code formatting conventions.

Some specific requirements:

* New configuration options must be documented in `doc/config.md` and
  added to the sample file `etc/pgbouncer.ini`.

* Do not edit the release notes in `NEWS.md` as part of feature
  changes or bug fixes. This file is updated when the release is
  prepared.

* Use the helpers in `lib/usual` where one exists. These are different
  from the helpers available for PostgreSQL core code.

* Unlike core PostgreSQL, PgBouncer uses plain malloc-style memory
  allocation, not memory contexts. So every piece of allocated memory
  must be carefully freed in all code paths, success or failure.

* For the time being, both build systems, Meson and Autoconf, need to
  be updated and kept in sync.

Some design considerations for new features:

* PgBouncer is part of the PostgreSQL ecosystem and should behave
  consistently with PostgreSQL. In particular, settings, options, or
  features that also exist in PostgreSQL or are named the same as in
  PostgreSQL should work consistently. It is ok to only support a
  subset of the functionality of the corresponding PostgreSQL feature,
  but that subset should behave consistently.

* On the other hand, PgBouncer is also sometimes used with components
  that use the PostgreSQL protocol but are not actually PostgreSQL or
  derived from PostgreSQL. This is not consistently tested, but it
  should not be broken gratuitously.

* PgBouncer is a protocol proxy and should implement the PostgreSQL
  protocol faithfully. If clarifications, changes, or enhancements to
  the protocol are to be considered, this should be discussed with the
  PostgreSQL development team.

## Dependencies

The required and optional library and tool dependencies are listed in
[README.md](README.md). In some cases, minimum versions are listed;
these represent what is known to be technically required to build or
run PgBouncer, but they are not meant as recommendations for which
versions users should use. Users (or packagers) are responsible for
selecting the versions of the dependencies and keeping them up to
date.

Changes to the minimum versions can be entertained when this would
support proposed new functionality or would enable cleaning up
significant amounts of code. When determining which range of versions
of a dependency to support, consider the default versions available on
operating systems that PgBouncer users would reasonably want to
use. Many (but not all) of these operating systems are covered in the
CI system. If raising a minimum version would break or require
dropping a platform covered by CI, that would require more careful
analysis and review.

New library dependencies can be added when a feature requires them,
but this should be done very rarely and then usually as an optional
build feature. Such additions would require careful review and
maintainer and community consensus.

The Python packages used by the test suite are configured in
`pyproject.toml`. Since the test dependencies are installed from PyPI
with pip (typically into a virtual environment), the packages
available on supported operating systems can be disregarded. But the
minimum supported Python version needs to be kept in mind: We must be
able to run the test suite on all supported operating systems. The
Python packages are intentionally not version-pinned, and so
installations get whatever releases are current at the time.

Special cases:

* `lib/usual/` is a fork of libusual and is maintained as part of
  PgBouncer. It is not synced from an upstream (anymore).

* `include/common/uthash.h` is a copy of uthash that is updated by
  hand. `include/common/uthash_lowercase.h` is derived from that and
  is also updated by hand.

* A number of files in `src/common/` and `include/common/` are copied
  from PostgreSQL. See `etc/import-common.sh` for details. These are
  updated by hand from time to time.

* The Windows release zip contains a `pgbouncer.exe` statically linked
  against OpenSSL and libevent from the MSYS2 packages current at the
  time of the release build. These libraries are only updated with new
  PgBouncer releases; users who need security fixes in them sooner
  should build PgBouncer themselves or find a different package
  source.
