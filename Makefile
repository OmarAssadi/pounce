PREFIX ?= /usr/local
MANDIR ?= ${PREFIX}/share/man

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -lcrypt -ltls

BINS = calico pounce
MANS = ${BINS:=.1}

-include config.mk

OBJS += bounce.o
OBJS += client.o
OBJS += config.o
OBJS += local.o
OBJS += ring.o
OBJS += server.o
OBJS += state.o
OBJS += xdg.o

dev: tags all

all: ${BINS}

calico: dispatch.o
	${CC} ${LDFLAGS} dispatch.o -o $@

pounce: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

${OBJS}: bounce.h

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f tags ${BINS} ${OBJS} dispatch.o

install: ${BINS} ${MANS}
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${MANDIR}/man1
	install ${BINS} ${DESTDIR}${PREFIX}/bin
	install -m 644 ${MANS} ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${BINS:%=${DESTDIR}${PREFIX}/bin/%}
	rm -f ${MANS:%=${DESTDIR}${MANDIR}/man1/%}

localhost.crt:
	printf "[dn]\nCN=localhost\n[req]\ndistinguished_name=dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth" \
		| openssl req -x509 -out localhost.crt -keyout localhost.key \
		-newkey rsa:2048 -nodes -sha256 \
		-subj '/CN=localhost' -extensions EXT -config /dev/fd/0
