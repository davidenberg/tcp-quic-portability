CC     = gcc
CFLAGS = -g -Wall -pedantic -shared -fPIC
RM     = rm -f

default: all

all: tcp2quic

tcp2quic:
	$(CC) $(CFLAGS) -o libtcp2quic.so tcp2quic.c

clean:
	$(RM) server client

.PHONY: all clean