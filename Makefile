LIBRESSL_PREFIX = /usr/local

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += -I${LIBRESSL_PREFIX}/include
LDFLAGS += -L${LIBRESSL_PREFIX}/lib
LDLIBS = -ltls

-include config.mk

linger:
