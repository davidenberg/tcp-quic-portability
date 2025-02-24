#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include "tcp2quic.h"
#include "../include/msquic.h"
#include "../include/msquic_posix.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#define FILE_DESCRIPTOR_LOWER 10000
#define MAX_LISTENERS 128
#define MAX_CONNECTIONS 128
#define LISTENER_IDX(X)                  (X - FILE_DESCRIPTOR_LOWER)

const QUIC_API_TABLE* MsQuic   = NULL;
HQUIC Registration             = NULL;
static int fd_count            = FILE_DESCRIPTOR_LOWER;
HQUIC Listeners[MAX_LISTENERS] = { 0 };
QUIC_ADDR Addresses[MAX_LISTENERS] = { 0 };

static int (*original_socket)(int, int, int) = NULL;
static int (*original_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*original_listen)(int, int) = NULL;
static int (*original_accept)(int, struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*original_read)(int, void *, size_t) = NULL;
static ssize_t (*original_write)(int, const void *, size_t) = NULL;
static int (*original_close)(int) = NULL;

static void init_originals() {
    if (!original_socket) {
        original_socket = dlsym(RTLD_NEXT, "socket");
        original_bind   = dlsym(RTLD_NEXT, "bind");
        original_listen = dlsym(RTLD_NEXT, "listen");
        original_accept = dlsym(RTLD_NEXT, "accept");
        original_read   = dlsym(RTLD_NEXT, "read");
        original_write  = dlsym(RTLD_NEXT, "write");
        original_close  = dlsym(RTLD_NEXT, "close");
    }
}

const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

QUIC_STATUS init_MsQuic()
{
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    if (MsQuic == NULL && QUIC_FAILED(status = MsQuicOpen2(&MsQuic)))
    {
        printf("Failed to init API table, status 0x%x!\n", status);
        goto err;
    }
    if (QUIC_FAILED(status = MsQuic->RegistrationOpen(NULL, &Registration)))
    {
        printf("Failed to open registration, status 0x%x!\n", status);
        goto err;
    }

    return status;

err:
    if (MsQuic != NULL)
    {
        if (Registration != NULL)
        {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return status;
}

QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Listener,
                                            void *ctx,
                                            QUIC_CONNECTION_EVENT *Event)
{
    //@TODO
    return QUIC_STATUS_INTERNAL_ERROR;
}

QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener,
                                            void *ctx,
                                            QUIC_LISTENER_EVENT *Event)
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(ctx);

    switch (Event->Type)
    {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
            //@TODO add configuration for certs etc.
            break;
        
        default:
            break;
    }
    return Status;
}

int socket(int domain, int type, int protocol)
{
    if (domain != AF_INET || type != SOCK_STREAM)
    {
        init_originals();
        return original_socket(domain, type, protocol);
    }
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    int fd;

    if (MsQuic == NULL || Registration == NULL)
    {
        if (QUIC_FAILED(status = init_MsQuic()))
        {
            goto err;
        }
        else
            printf("Initialized MsQuic\n");
    }

    fd = fd_count++;
    if (QUIC_FAILED(status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listeners[LISTENER_IDX(fd)])))
    {
        printf("ListenerOpen failed, 0x%x!\n", status);
        goto err;
    }

    printf("Created listener()\n");
    return fd;

err:
    errno = status;
    return -1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (sockfd < FILE_DESCRIPTOR_LOWER ||
        addr->sa_family != AF_INET ||
        !Listeners[LISTENER_IDX(sockfd)])
    {
        init_originals();
        return original_bind(sockfd, addr, addrlen);
    }

    QuicAddrSetFamily(&Addresses[LISTENER_IDX(sockfd)], QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&Addresses[LISTENER_IDX(sockfd)], ntohs(((struct sockaddr_in*)addr)->sin_port));

    QUIC_ADDR_STR addrStr = { 0 };

    printf("Stored socket address and port\n");
    return 0;
}


int listen(int sockfd, int backlog)
{
    if (!Listeners[LISTENER_IDX(sockfd)] ||
        QuicAddrGetFamily(&Addresses[LISTENER_IDX(sockfd)]) != AF_INET)
    {
        init_originals();
        return original_listen(sockfd, backlog);
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listeners[LISTENER_IDX(sockfd)], &Alpn, 1, &Addresses[LISTENER_IDX(sockfd)])))
    {
        printf("ListenerStart failed, 0x%x!\n", Status);
        errno = Status;
        return -1;
    }
    QUIC_ADDR_STR addrStr = { 0 };
    if (QuicAddrToString(&Addresses[LISTENER_IDX(sockfd)], &addrStr))
        printf("QUIC: Start listening on %s\n", addrStr.Address);

    return 0;
}

/*
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
*/