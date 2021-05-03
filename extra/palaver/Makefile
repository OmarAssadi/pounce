PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
MANDIR ?= ${PREFIX}/man

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDADD.libcurl = -lcurl
LDADD.libtls = -ltls
LDADD.sqlite3 = -lsqlite3

-include config.mk

LDLIBS = ${LDADD.libcurl} ${LDADD.libtls} ${LDADD.sqlite3}
OBJS = notify.o

all: pounce-palaver

pounce-palaver: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

clean:
	rm -f ${OBJS} pounce-palaver

install: pounce-palaver pounce-palaver.1
	install -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}/man1
	install pounce-palaver ${DESTDIR}${BINDIR}
	install -m 644 pounce-palaver.1 ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${DESTDIR}${BINDIR}/pounce-palaver
	rm -f ${DESTDIR}${MANDIR}/man1/pounce-palaver.1
