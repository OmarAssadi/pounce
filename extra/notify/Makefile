PREFIX ?= /usr/local
MANDIR ?= ${PREFIX}/share/man

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -ltls

-include config.mk

OBJS = notify.o

all: pounce-notify

pounce-notify: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

clean:
	rm -f ${OBJS} pounce-notify

install: pounce-notify pounce-notify.1
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${MANDIR}/man1
	install pounce-notify ${DESTDIR}${PREFIX}/bin
	install -m 644 pounce-notify.1 ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/pounce-notify
	rm -f ${DESTDIR}${MANDIR}/man1/pounce-notify.1
