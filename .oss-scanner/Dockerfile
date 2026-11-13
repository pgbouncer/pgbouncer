# Test environment for the Anthropic OSS Scanner (https://red.anthropic.com/oss-scanner), built with
# the repository root as context:
#
#   docker build -f .oss-scanner/Dockerfile -t pgbouncer-dev .

# trixie rather than bookworm, because bookworm's gcc 12 ASan runtime hangs in an endless
# "AddressSanitizer:DEADLYSIGNAL" loop on kernels with high vm.mmap_rnd_bits.
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive \
    PGVERSION=17

# Build dependencies, plus what the test suite needs: a PostgreSQL server, socat, and slapd for the
# LDAP tests. Debuggers and the like are not needed here, because the scanner adds its own layer
# with those. The tests that simulate network failures need sudo, iptables and tc, and are skipped
# because USE_SUDO is not set.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates gcc ldap-utils libc-ares-dev libc6-dev libevent-dev libldap-dev \
      libpam0g-dev libssl-dev meson ninja-build pkg-config "postgresql-$PGVERSION" python3 \
      python3-venv slapd socat \
    && rm -rf /var/lib/apt/lists/*

# The scanner expects the checkout inside the image at /src.
COPY . /src
WORKDIR /src

# pgbouncer and initdb refuse to run as root, so the test suite has to run as an unprivileged user.
# The scanner's own layer switches back to root, so from there run the tests with e.g.
# `runuser -u user -- meson test -C build`.
RUN useradd -m user && chown -R user /src
USER user

# pyproject.toml only declares the Python test dependencies (pytest, psycopg, ...), so this
# installs those rather than a package.
RUN python3 -m venv /home/user/venv && /home/user/venv/bin/pip install /src
ENV PATH=/home/user/venv/bin:/usr/lib/postgresql/$PGVERSION/bin:$PATH

# Sanitizers and assertions turn memory errors and broken invariants into immediate crashes with a
# stack trace, instead of silent corruption, which makes findings much easier to confirm. The
# sanitizer flags are the same as in the asan+ubsan CI job.
RUN CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all -fno-sanitize=shift" \
      LDFLAGS="-fsanitize=address,undefined" \
      meson setup build -Dcassert=true -Dcares=enabled -Dldap=enabled -Dpam=enabled \
    && meson compile -C build
