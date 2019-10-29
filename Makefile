PREFIX = /usr/local
MANDIR = ${PREFIX}/man
ETCDIR = ${PREFIX}/etc
LIBRESSL_PREFIX = /usr/local

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += -I${LIBRESSL_PREFIX}/include
LDFLAGS += -L${LIBRESSL_PREFIX}/lib
LDLIBS = -ltls

-include config.mk

OBJS += bounce.o
OBJS += client.o
OBJS += config.o
OBJS += listen.o
OBJS += ring.o
OBJS += server.o
OBJS += state.o

all: tags pounce

pounce: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

${OBJS}: bounce.h

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f tags pounce ${OBJS}

install: pounce pounce.1 rc.pounce
	install -d ${PREFIX}/bin ${MANDIR}/man1 ${ETCDIR}/rc.d
	install pounce ${PREFIX}/bin
	install -m 644 pounce.1 ${MANDIR}/man1
	install rc.pounce ${ETCDIR}/rc.d/pounce

uninstall:
	rm -f ${PREFIX}/bin/pounce ${MANDIR}/man1/pounce.1 ${ETCDIR}/rc.d/pounce
