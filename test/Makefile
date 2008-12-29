
PGINC = -I$(shell pg_config --includedir)
PGLIB = -L$(shell pg_config --libdir)

include ../config.mak

CPPFLAGS += -I../include $(PGINC)
LDFLAGS += $(PGLIB)
LIBS := -lpq $(LIBS)

ifeq ($(PORTNAME),win32)
CPPFLAGS += -I../win32
endif

all: asynctest

asynctest: asynctest.c
	$(CC) -o $@ $< $(DEFS) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(LIBS)

clean:
	rm -f asynctest

