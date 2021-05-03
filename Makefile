PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
MANDIR ?= ${PREFIX}/man

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDADD.crypt = -lcrypt
LDADD.libtls = -ltls

BINS = calico pounce
MANS = ${BINS:=.1}

-include config.mk

LDLIBS.calico =
LDLIBS.pounce = ${LDADD.crypt} ${LDADD.libtls}

OBJS.calico += dispatch.o

OBJS.pounce += bounce.o
OBJS.pounce += cert.o
OBJS.pounce += client.o
OBJS.pounce += config.o
OBJS.pounce += local.o
OBJS.pounce += ring.o
OBJS.pounce += server.o
OBJS.pounce += state.o
OBJS.pounce += xdg.o

OBJS = ${OBJS.calico} ${OBJS.pounce}

dev: tags all

all: ${BINS}

calico: ${OBJS.calico}

pounce: ${OBJS.pounce}

${BINS}:
	${CC} ${LDFLAGS} ${OBJS.$@} ${LDLIBS.$@} -o $@

${OBJS.pounce}: bounce.h

tags: *.[ch]
	ctags -w *.[ch]

clean:
	rm -f ${BINS} ${OBJS} tags

install: ${BINS} ${MANS}
	install -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}/man1
	install ${BINS} ${DESTDIR}${BINDIR}
	install -m 644 ${MANS} ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${BINS:%=${DESTDIR}${BINDIR}/%}
	rm -f ${MANS:%=${DESTDIR}${MANDIR}/man1/%}

localhost.pem: pounce
	./pounce -g $@
