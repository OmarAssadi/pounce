CFLAGS += -DNO_EXPLICIT_BZERO
LDLIBS := ${LDLIBS:-lcrypt=}