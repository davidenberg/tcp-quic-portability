#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 4443
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    ssize_t rx_count;
    ssize_t tx_count;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d...\n", PORT);

    while(1) {

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        rx_count = read(new_socket, buffer, BUFFER_SIZE - 1);
        if (rx_count < 0) {
            perror("read");
            close(new_socket);
            continue;
        }
        buffer[rx_count] = '\0';
        printf("Received: %s\n", buffer);
        
        const char *response = "Hello from server";
        tx_count = send(new_socket, response, strlen(response), 0);
        printf("Response sent, %zd bytes\n", tx_count);

        close(new_socket);
    }

    close(server_fd);
    return 0;
}