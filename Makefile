CC     = gcc
CFLAGS = -g -Wall
RM     = rm -f

SERVER_SRC = src/server
CLIENT_SRC = src/client
LIB_SRC    = lib

dir_guard=mkdir -p bin 

default: all

all: Server Client Library Test

Server: $(SERVER_SRC)/server.c
	$(dir_guard)
	$(CC) $(CFLAGS) -o bin/server $(SERVER_SRC)/server.c

Client: $(CLIENT_SRC)/client.c
	$(dir_guard)
	$(CC) $(CFLAGS) -o bin/client $(CLIENT_SRC)/client.c

Library:
	$(CC) $(CFLAGS) -shared -fPIC -O3 -finline-functions -o lib/libtcp2quic.so $(LIB_SRC)/tcp2quic.c -lmsquic -ldl

Test:
	$(CC) $(CFLAGS) -o bin/perf_server src/testing/server/server.c
	$(CC) $(CFLAGS) -o bin/perf_client src/testing/client/client.c

clean:
	$(RM) bin/server bin/client lib/libtcp2quic.so
	$(RM) -r bin

.PHONY: all clean