#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 4443
#define BUFFER_SIZE 1024 * 1024
#define TOTAL_SIZE_MB 1000L

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main() {
    int                server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t          addrlen = sizeof(address);
    char               *buffer = malloc(BUFFER_SIZE);
    char               *read_buf[1024];
    if (!buffer)
        error("Memory allocation failed");

    memset(buffer, 'A', BUFFER_SIZE);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        error("Socket failed");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        error("Bind failed");

    if (listen(server_fd, 1) < 0)
        error("Listen failed");

    printf("Server listening on port %d...\n", PORT);
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0)
        error("Accept failed");

    printf("Client connected. Sending data...\n");
    read(new_socket, read_buf, 1024 - 1);
    size_t bytes_sent = 0;
    while (bytes_sent < TOTAL_SIZE_MB * 1024 * 1024) {
        ssize_t sent = send(new_socket, buffer, BUFFER_SIZE, 0);
        if (sent < 0)
            error("Send error");
        bytes_sent += sent;
    }

    close(new_socket);
    close(server_fd);
    free(buffer);
    return 0;
}
