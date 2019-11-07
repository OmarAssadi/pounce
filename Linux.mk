CFLAGS += -D_GNU_SOURCE -D'CERTBOT_PATH="/etc/letsencrypt"'
LDLIBS = -lcrypt -lpthread -l:libtls.a -l:libssl.a -l:libcrypto.a

MANDIR = ${PREFIX}/share/man
ETCDIR = /etc
RCS =
DIRS =
