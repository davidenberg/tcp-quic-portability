CC     = gcc
CFLAGS = -g -Wall -pedantic
RM     = rm -f

SERVER_SRC = src/server
CLIENT_SRC = src/client

dir_guard=mkdir -p bin 

default: all

all: Server Client

Server: $(SERVER_SRC)/server.c
	$(dir_guard)
	$(CC) $(CFLAGS) -o bin/server $(SERVER_SRC)/server.c

Client: $(CLIENT_SRC)/client.c
	$(dir_guard)
	$(CC) $(CFLAGS) -o bin/client $(CLIENT_SRC)/client.c

clean:
	$(RM) bin/server bin/client
	$(RM) -r bin

.PHONY: all clean