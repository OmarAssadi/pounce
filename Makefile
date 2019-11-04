PREFIX = /usr/local
MANDIR = ${PREFIX}/man
ETCDIR = ${PREFIX}/etc
LIBRESSL_PREFIX = /usr/local

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += -I${LIBRESSL_PREFIX}/include
LDFLAGS += -L${LIBRESSL_PREFIX}/lib
LDLIBS = -lcrypt -ltls

BINS = calico pounce
MANS = ${BINS:=.1}
RCS  = ${BINS:%=rc.d/%}
DIRS = ${ETCDIR}/pounce /var/run/calico

-include config.mk

OBJS += bounce.o
OBJS += client.o
OBJS += config.o
OBJS += listen.o
OBJS += ring.o
OBJS += server.o
OBJS += state.o

all: tags ${BINS}

calico: dispatch.o
	${CC} ${LDFLAGS} dispatch.o -o $@

pounce: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

${OBJS}: bounce.h

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f tags ${BINS} ${OBJS} dispatch.o

install: ${BINS} ${MANS} ${RCS}
	install -d ${PREFIX}/bin ${MANDIR}/man1 ${ETCDIR}/rc.d
	install ${BINS} ${PREFIX}/bin
	install -m 644 ${MANS} ${MANDIR}/man1
	install ${RCS} ${ETCDIR}/rc.d
	install -d -m 700 ${DIRS}

uninstall:
	rm -f ${BINS:%=${PREFIX}/bin/%}
	rm -f ${MANS:%=${MANDIR}/man1/%}
	rm -f ${RCS:%=${ETCDIR}/%}
	rmdir ${DIRS}

localhost.crt:
	printf "[dn]\nCN=localhost\n[req]\ndistinguished_name=dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth" \
		| openssl req -x509 -out localhost.crt -keyout localhost.key \
		-newkey rsa:2048 -nodes -sha256 \
		-subj '/CN=localhost' -extensions EXT -config /dev/fd/0
