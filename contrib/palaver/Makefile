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

.SUFFIXES: .in

.in:
	sed -e 's|%%PREFIX%%|${PREFIX}|g' $< > $@

clean:
	rm -f ${OBJS} pounce-palaver rc.d/pounce_palaver

install: pounce-palaver pounce-palaver.1 ${INSTALLS}
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${MANDIR}/man1
	install pounce-palaver ${DESTDIR}${PREFIX}/bin
	install -m 644 pounce-palaver.1 ${DESTDIR}${MANDIR}/man1

install-rcs: rc.d/pounce_palaver
	install -d ${DESTDIR}${ETCDIR}/rc.d
	install rc.d/pounce_palaver ${DESTDIR}${ETCDIR}/rc.d

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/pounce-palaver
	rm -f ${DESTDIR}${MANDIR}/man1/pounce-palaver.1
	rm -f ${DESTDIR}${ETCDIR}/rc.d/pounce_palaver
