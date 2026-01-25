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
RUN mkdir -p /src /build && chown user:user /build

WORKDIR /build

# Copy the build script
COPY --chmod=755 <<'EOF' /usr/local/bin/build
#!/bin/bash
set -e

cd /build

# Check if configure exists in source
if [ ! -f /src/configure ]; then
    echo "Error: /src/configure not found."
    echo "Run './autogen.sh' in your source directory first."
    exit 1
fi

# Run configure if Makefile doesn't exist (out-of-tree build)
if [ ! -f Makefile ]; then
    echo "==> Running configure (out-of-tree build)..."
    /src/configure --prefix=/build/install --enable-cassert --with-cares --with-pam --with-ldap --with-systemd
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

USER user
