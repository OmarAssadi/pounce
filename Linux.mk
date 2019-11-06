CFLAGS += -D_GNU_SOURCE -D'CERTBOT_PATH="/etc/letsencrypt"'
LDLIBS = -lcrypt -lpthread
LDLIBS += ${LIBRESSL_PREFIX}/lib/libtls.a
LDLIBS += ${LIBRESSL_PREFIX}/lib/libssl.a
LDLIBS += ${LIBRESSL_PREFIX}/lib/libcrypto.a
