CFLAGS  := -pipe -Wall -Wextra -Wno-type-limits
ARFLAGS := rv
TARGETS := wscat

.PHONY: clean

ifdef DEBUG
  CFLAGS += -O0 -g
else
  CFLAGS += -O2 -DNDEBUG
  LDFLAGS += -s
endif

ifdef IOFUZZ
  CFLAGS += -DIOFUZZ
endif

all: $(TARGETS)

inet.o: inet.c inet.h
libinet.a: libinet.a(inet.o)

base64.o: base64.c base64.h
sha1.o: sha1.c sha1.h
ws.o: ws.c ws.h
libws.a: libws.a(ws.o) libws.a(sha1.o) libws.a(base64.o)

wscat.o: wscat.c libinet.a libws.a common.h 

wscat: LDLIBS  += -linet -lws
wscat: LDFLAGS += -L.

clean:
	rm -f $(TARGETS) *.a *.o

