#include <sys/socket.h>
#include <stdio.h>
//Declare functions
int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int close(int fd);

int socket(int domain, int type, int protocol)
{
    printf("socket() called\n");
    return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    printf("bind() called\n");
    return 0;
}

int listen(int sockfd, int backlog)
{
    printf("listen() called\n");
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    printf("accept() called\n");
    return 0;
}
ssize_t read(int fd, void *buf, size_t count)
{
    printf("read() called\n");
    return 0;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    printf("write() called\n");
    return 0;
}

int close(int fd)
{
    printf("close() called\n");
    return 0;
}
