FROM public.ecr.aws/amazonlinux/amazonlinux:2023

RUN yum -y update
RUN yum install -y tar net-tools curl vim unzip less libevent-devel openssl-devel python-devel libtool git patch make gcc wget --allowerasing

# Install pandoc
RUN ARCH="" && if [ "$(uname -m)" = "x86_64" ]; then ARCH='amd64'; else ARCH='arm64'; fi && export ${ARCH} && \
    wget https://github.com/jgm/pandoc/releases/download/3.1.6.2/pandoc-3.1.6.2-linux-${ARCH}.tar.gz && \
    tar xvzf ./pandoc-3.1.6.2-linux-${ARCH}.tar.gz --strip-components 1 -C /usr/local

COPY . ./pgbouncer/
RUN cd ./pgbouncer/ && \
    git submodule init && \
    git submodule update && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local --exec-prefix=/usr/bin --bindir=/usr/bin && \
    make && \
    make install

# Installed with pgbouncer
RUN useradd -ms /bin/bash pgbouncer && \
    chown pgbouncer /home/pgbouncer && \
    chown pgbouncer /

USER pgbouncer
WORKDIR /home/pgbouncer

COPY ./start.sh /start.sh
COPY ./routing_rules.py /home/pgbouncer/
