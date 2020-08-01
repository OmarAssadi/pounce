PREFIX ?= /usr/local
MANDIR ?= ${PREFIX}/share/man
ETCDIR ?= ${PREFIX}/etc
RUNDIR ?= /var/run

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -lcrypt -ltls

BINS = calico pounce
MANS = ${BINS:=.1}
RCS  = ${BINS:%=rc.d/%}
DIRS = ${ETCDIR}/pounce ${RUNDIR}/calico

-include config.mk

OBJS += bounce.o
OBJS += client.o
OBJS += config.o
OBJS += local.o
OBJS += ring.o
OBJS += server.o
OBJS += state.o

dev: tags all

all: ${BINS}

calico: dispatch.o
	${CC} ${LDFLAGS} dispatch.o -o $@

pounce: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

${OBJS}: bounce.h

.SUFFIXES: .in

.in:
	sed -e 's|%%PREFIX%%|${PREFIX}|g' $< > $@

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f tags ${BINS} ${RCS} ${OBJS} dispatch.o

install: ${BINS} ${MANS} ${INSTALLS}
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${MANDIR}/man1
	install ${BINS} ${DESTDIR}${PREFIX}/bin
	install -m 644 ${MANS} ${DESTDIR}${MANDIR}/man1

install-rcs: ${RCS}
	install -d ${DESTDIR}${ETCDIR}/rc.d
	install ${RCS} ${DESTDIR}${ETCDIR}/rc.d

install-dirs:
	install -d ${DIRS:%=${DESTDIR}%}

uninstall:
	rm -f ${BINS:%=${DESTDIR}${PREFIX}/bin/%}
	rm -f ${MANS:%=${DESTDIR}${MANDIR}/man1/%}
	rm -f ${RCS:%=${DESTDIR}${ETCDIR}/%}

localhost.crt:
	printf "[dn]\nCN=localhost\n[req]\ndistinguished_name=dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth" \
		| openssl req -x509 -out localhost.crt -keyout localhost.key \
		-newkey rsa:2048 -nodes -sha256 \
		-subj '/CN=localhost' -extensions EXT -config /dev/fd/0
