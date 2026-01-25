FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C
ENV PGVERSION=16

# Install PostgreSQL repo
RUN apt-get update && \
    apt-get -y --no-install-recommends install gnupg postgresql-common ca-certificates && \
    /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y && \
    apt-get update

# Install build dependencies
RUN apt-get -y --no-install-recommends install \
    autoconf \
    automake \
    ca-certificates \
    cpio \
    git \
    iptables \
    iproute2 \
    ldap-utils \
    libc-ares-dev \
    libevent-dev \
    libldap-dev \
    libpam0g-dev \
    libssl-dev \
    libsystemd-dev \
    libtool \
    make \
    pandoc \
    pkg-config \
    postgresql-${PGVERSION} \
    python3 \
    python3-pip \
    python3-venv \
    rsync \
    slapd \
    socat \
    sudo

# Create virtual environment for Python dependencies
RUN python3 -m venv /venv
COPY requirements.txt /tmp/requirements.txt
RUN /venv/bin/pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Create non-root user for building/testing
RUN useradd -m -s /bin/bash user && \
    echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Set up PATH for PostgreSQL binaries
ENV PATH="/usr/lib/postgresql/${PGVERSION}/bin:/venv/bin:${PATH}"

# Create directories
RUN mkdir -p /source /build && chown user:user /build

WORKDIR /build

# Copy the build script
COPY --chmod=755 <<'EOF' /usr/local/bin/build
#!/bin/bash
set -e

cd /build

# Sync source from /source to /build (excludes .git and test which is a separate mount)
echo "==> Syncing source..."
rsync -a --delete --exclude='.git' --exclude='test' /source/ /build/

# Run autogen.sh if configure doesn't exist
if [ ! -f configure ]; then
    echo "==> Running autogen.sh..."
    ./autogen.sh
fi

# Run configure if Makefile doesn't exist or configure.ac is newer
if [ ! -f Makefile ] || [ configure.ac -nt Makefile ]; then
    echo "==> Running configure..."
    ./configure --prefix=/build/install --enable-cassert --with-cares --with-pam --with-ldap --with-systemd
fi

echo "==> Building..."
make -j$(nproc)

echo "==> Build complete!"
EOF

COPY --chmod=755 <<'EOF' /usr/local/bin/run-tests
#!/bin/bash
set -e

cd /build

# Ensure we're built first
if [ ! -f /build/pgbouncer ]; then
    echo "Error: pgbouncer not built yet. Run 'build' first."
    exit 1
fi

echo "==> Running tests..."
source /venv/bin/activate

# Default to 4 parallel test workers
CONCURRENCY=${CONCURRENCY:-4}

make check CONCURRENCY=$CONCURRENCY "$@"
EOF

# Script to sync only (without building)
COPY --chmod=755 <<'EOF' /usr/local/bin/sync-src
#!/bin/bash
set -e
echo "==> Syncing source from /source to /build..."
rsync -a --delete --exclude='.git' --exclude='test' /source/ /build/
echo "==> Done."
EOF

USER user
