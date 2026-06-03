FROM debian:bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    autoconf \
    automake \
    libtool \
    libevent-dev \
    libssl-dev \
    libc-ares-dev \
    libpam0g-dev \
    libldap2-dev \
    python3 \
    pandoc \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN ./autogen.sh \
    && ./configure --prefix=/usr/local --with-cares --with-pam --with-ldap \
    && make -j"$(nproc)" \
    && make install

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libevent-2.1-7 \
    libssl3 \
    libc-ares2 \
    libpam0g \
    libldap-2.5-0 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r pgbouncer && useradd -r -g pgbouncer -u 1000 pgbouncer \
    && mkdir -p /etc/pgbouncer \
    && chown pgbouncer:pgbouncer /etc/pgbouncer

COPY --from=build /usr/local/bin/pgbouncer /usr/local/bin/pgbouncer

USER 1000
EXPOSE 6432

ENTRYPOINT ["pgbouncer"]
CMD ["/etc/pgbouncer/pgbouncer.ini"]
