FROM alpine:latest AS build_stage

MAINTAINER chris@chriscowley.me.uk

WORKDIR /src
RUN apk --no-cache add git python py-pip build-base automake libtool m4 \
                     autoconf libevent-dev openssl-dev c-ares-dev
RUN pip install docutils
COPY . /src/
RUN ln -sv ../usr/bin/rst2man.py /bin/rst2man

WORKDIR /src
RUN mkdir /pgbouncer
RUN git submodule init
RUN git submodule update
RUN ./autogen.sh && ./configure --prefix=/pgbouncer --with-libevent=/usr/lib
RUN make
RUN make install
RUN ls -R /pgbouncer

FROM alpine:latest
RUN apk --no-cache add libevent openssl c-ares
WORKDIR /
COPY --from=build_stage /pgbouncer /pgbouncer
ADD entrypoint.sh ./
ENTRYPOINT ["./entrypoint.sh"]
