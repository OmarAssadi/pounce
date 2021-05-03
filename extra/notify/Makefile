PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
MANDIR ?= ${PREFIX}/man

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDADD.libtls = -ltls

-include config.mk

LDLIBS = ${LDADD.libtls}
OBJS = notify.o

all: pounce-notify

pounce-notify: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

clean:
	rm -f ${OBJS} pounce-notify

install: pounce-notify pounce-notify.1
	install -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}/man1
	install pounce-notify ${DESTDIR}${BINDIR}
	install -m 644 pounce-notify.1 ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${DESTDIR}${BINDIR}/pounce-notify
	rm -f ${DESTDIR}${MANDIR}/man1/pounce-notify.1
