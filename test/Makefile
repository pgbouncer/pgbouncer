
PGINC = -I$(shell pg_config --includedir)
PGLIB = -L$(shell pg_config --libdir)

include ../config.mak

CPPFLAGS += -I../include $(PGINC)
LDFLAGS += $(PGLIB) -lpq -levent

all: asynctest

asynctest: asynctest.c
	$(CC) -o $@ $< $(CPPFLAGS) $(CFLAGS) $(LDFLAGS)

clean:
	rm -f asynctest

