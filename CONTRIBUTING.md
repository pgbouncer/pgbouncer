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
