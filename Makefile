PREFIX = /usr/local
MANDIR = ${PREFIX}/share/man
ETCDIR = ${PREFIX}/etc

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -lcrypt -lcrypto -ltls

BINS = calico pounce
MANS = ${BINS:=.1}
RCS  = ${BINS:%=rc.d/%}
DIRS = ${ETCDIR}/pounce /var/run/calico

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
	${CC} ${LDFLAGS} dispatch.o ${LDLIBS.calico} -o $@

pounce: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

${OBJS}: bounce.h compat.h

dispatch.o: compat.h

.SUFFIXES: .in

.in:
	sed -e 's|%%PREFIX%%|${PREFIX}|g' $< > $@

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f tags ${BINS} ${RCS} ${OBJS} dispatch.o

install: ${BINS} ${MANS} ${RCS}
	install -d ${PREFIX}/bin ${MANDIR}/man1
	install ${BINS} ${PREFIX}/bin
	install -m 644 ${MANS} ${MANDIR}/man1
	if [ -n '${RCS}' ]; then install -d ${ETCDIR}/rc.d; fi
	if [ -n '${RCS}' ]; then install ${RCS} ${ETCDIR}/rc.d; fi
	if [ -n '${DIRS}' ]; then install -d ${DIRS}; fi

uninstall:
	rm -f ${BINS:%=${PREFIX}/bin/%}
	rm -f ${MANS:%=${MANDIR}/man1/%}
	if [ -n '${RCS}' ]; then rm -f ${RCS:%=${ETCDIR}/%}; fi
	if [ -n '${DIRS}' ]; then rmdir ${DIRS}; fi

localhost.crt:
	printf "[dn]\nCN=localhost\n[req]\ndistinguished_name=dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth" \
		| openssl req -x509 -out localhost.crt -keyout localhost.key \
		-newkey rsa:2048 -nodes -sha256 \
		-subj '/CN=localhost' -extensions EXT -config /dev/fd/0
