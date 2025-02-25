int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

ssize_t write(int fd, const void *buf, size_t count);
ssize_t send(int socket, const void *buffer, size_t length, int flags);
ssize_t read(int fd, void *buf, size_t count);
/*
int close(int fd);
*/