LIBRESSL_PREFIX = /usr/local

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += -I${LIBRESSL_PREFIX}/include
LDFLAGS += -L${LIBRESSL_PREFIX}/lib
LDLIBS = -ltls

-include config.mk

OBJS += bounce.o
OBJS += listen.o
OBJS += server.o

all: tags linger

linger: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

${OBJS}: bounce.h

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f tags linger ${OBJS}
