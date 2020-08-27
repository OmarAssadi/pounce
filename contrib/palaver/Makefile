PREFIX ?= /usr/local
MANDIR ?= ${PREFIX}/share/man
ETCDIR ?= ${PREFIX}/etc

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -lcurl -lsqlite3 -ltls

-include config.mk

OBJS = notify.o

all: pounce-palaver

pounce-palaver: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

clean:
	rm -f ${OBJS} pounce-palaver

install: pounce-palaver pounce-palaver.1
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${MANDIR}/man1
	install pounce-palaver ${DESTDIR}${PREFIX}/bin
	install -m 644 pounce-palaver.1 ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/pounce-palaver
	rm -f ${DESTDIR}${MANDIR}/man1/pounce-palaver.1
