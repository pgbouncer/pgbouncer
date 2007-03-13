
PGINC = -I$(shell pg_config --includedir)
PGLIB = -L$(shell pg_config --libdir)

CFLAGS = -O2 -g -Wall $(PGINC) -I$(HOME)/src/libevent -I../src
LDFLAGS = $(PGLIB) -lpq -L$(HOME)/src/libevent/.libs -levent

all: asynctest

asynctest: asynctest.c

clean:
	rm -f asynctest

