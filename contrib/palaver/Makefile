CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -lcurl -lsqlite3 -ltls

-include config.mk

OBJS = notify.o

pounce-palaver: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} ${LDLIBS} -o $@

clean:
	rm -f pounce-palaver ${OBJS}
