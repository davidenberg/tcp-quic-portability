#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>

#define SERVER_IP "127.0.0.1"
#define PORT 4443
#define BUFFER_SIZE 1024 * 1024
#define TOTAL_SIZE_MB 1000L

size_t bytes_received = 0;

void error(const char *msg) {
    perror(msg);
    exit(1);
}

enum { NS_PER_SECOND = 1000000000 };

void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td)
{
    td->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    td->tv_sec  = t2.tv_sec - t1.tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0)
    {
        td->tv_nsec += NS_PER_SECOND;
        td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0)
    {
        td->tv_nsec -= NS_PER_SECOND;
        td->tv_sec++;
    }
}

void receive_data(int sock)
{
    char *buffer = malloc(BUFFER_SIZE);
    
    while (bytes_received < TOTAL_SIZE_MB * 1024 * 1024) {
        ssize_t received = read(sock, buffer, BUFFER_SIZE - 1);
        if (received <= 0)
            break;
        bytes_received += received;

    }
    return;
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char               *buffer = malloc(BUFFER_SIZE);
    if (!buffer)
        error("Memory allocation failed");

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error("Socket creation failed");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0)
        error("Invalid address");

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) error("Connection failed");
    printf("Connected to server. Receiving data...\n");
    send(sock, "Teststring", strlen("Teststring"), 0);

    struct timespec start, finish, delta;
    clock_gettime(CLOCK_REALTIME, &start);
    receive_data(sock);
    clock_gettime(CLOCK_REALTIME, &finish);
    sub_timespec(start, finish, &delta);
    double time_taken = (double) delta.tv_sec + (double) delta.tv_nsec / 1000000000;
    printf("Data received: %ld MB\n", bytes_received / (1024 * 1024));
    printf("Time taken: %.2f seconds\n", time_taken);
    printf("Throughput: %.2f MB/s\n", (bytes_received / (1024  *1024)) / time_taken);

    close(sock);
    free(buffer);
    return 0;
}