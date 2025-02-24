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
#define LISTENER_IDX(X)                  ((int)X - FILE_DESCRIPTOR_LOWER)

const QUIC_API_TABLE* MsQuic   = NULL;
HQUIC Registration             = NULL;
HQUIC Configuration            = NULL;
static int fd_count            = FILE_DESCRIPTOR_LOWER;
HQUIC Listeners[MAX_LISTENERS] = { 0 };
QUIC_ADDR Addresses[MAX_LISTENERS] = { 0 };
HQUIC Connections[MAX_CONNECTIONS] = { 0 };

static int (*original_socket)(int, int, int) = NULL;
static int (*original_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*original_listen)(int, int) = NULL;
static int (*original_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*original_accept)(int, struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*original_read)(int, void *, size_t) = NULL;
static ssize_t (*original_write)(int, const void *, size_t) = NULL;
static int (*original_close)(int) = NULL;

static void init_originals() {
    if (!original_socket) {
        original_socket  = dlsym(RTLD_NEXT, "socket");
        original_bind    = dlsym(RTLD_NEXT, "bind");
        original_listen  = dlsym(RTLD_NEXT, "listen");
        original_connect = dlsym(RTLD_NEXT, "connect");
        original_accept  = dlsym(RTLD_NEXT, "accept");
        original_read    = dlsym(RTLD_NEXT, "read");
        original_write   = dlsym(RTLD_NEXT, "write");
        original_close   = dlsym(RTLD_NEXT, "close");
    }
}

const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

QUIC_STATUS init_MsQuic()
{
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (MsQuic == NULL && QUIC_FAILED(status = MsQuicOpen2(&MsQuic)))
    {
        printf("QUIC: Failed to init API table, status 0x%x!\n", status);
        goto err;
    }
    if (QUIC_FAILED(status = MsQuic->RegistrationOpen(NULL, &Registration)))
    {
        printf("QUIC: Failed to open registration, status 0x%x!\n", status);
        goto err;
    }

    QUIC_SETTINGS Settings = {0};
    Settings.IdleTimeoutMs = 1000;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    if (QUIC_FAILED(status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration)))
    {
        printf("QUIC: ConfigurationOpen failed, 0x%x!\n", status);
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
        if (Configuration != NULL)
        {
            MsQuic->ConfigurationClose(Configuration);
        }
        MsQuicClose(MsQuic);
    }

    return status;
}

QUIC_STATUS QUIC_API StreamCallback(HQUIC Stream,
                                    void *ctx,
                                    QUIC_STREAM_EVENT *Event)
{
    UNREFERENCED_PARAMETER(ctx);
    switch (Event->Type)
    {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            free(Event->SEND_COMPLETE.ClientContext);
            printf("[strm][%p] Data sent\n", Stream);
            break;
        case QUIC_STREAM_EVENT_RECEIVE:
            printf("[strm][%p] Data received\n", Stream);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            printf("[strm][%p] Peer shut down\n", Stream);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            printf("[strm][%p] Peer aborted\n", Stream);
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            printf("[strm][%p] All done\n", Stream);
            MsQuic->StreamClose(Stream);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ServerConnectionCallback(HQUIC Connection,
                                              void *ctx,
                                              QUIC_CONNECTION_EVENT *Event)
{
    switch (Event->Type)
    {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            printf("[conn][%p] Connected\n", Connection);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            printf("[conn][%p] All done\n", Connection);
            MsQuic->ConnectionClose(Connection);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)StreamCallback, NULL);
            break;
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ClientConnectionCallback(HQUIC Connection,
                                              void *ctx,
                                              QUIC_CONNECTION_EVENT *Event)
{
    switch (Event->Type)
    {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            int sockfd = *(int*)ctx;
            //Connections[LISTENER_IDX(sockfd)] = Connection;
            printf("[conn][%p] Connected\n", Connection);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            printf("[conn][%p] All done\n", Connection);
            if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress)
            {
                MsQuic->ConnectionClose(Connection);
            }
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API ServerListenerCallback(HQUIC Listener,
                                            void *ctx,
                                            QUIC_LISTENER_EVENT *Event)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(ctx);

    switch (Event->Type)
    {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION:
            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
            Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
            int sockfd = *(int*)ctx;
            //Connections[LISTENER_IDX(sockfd)] = Event->NEW_CONNECTION.Connection;
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

    if (MsQuic == NULL || Registration == NULL || Configuration == NULL)
    {
        if (QUIC_FAILED(status = init_MsQuic()))
        {
            goto err;
        }
        else
            printf("Initialized MsQuic\n");
    }

    /*
     *"Reserve" a slot for the connection/listener in the storage array to
     * return a mock file descriptor corresponding to the caller, don't allocate
     * a listener/connection quite yet.
     */
    fd = fd_count++;
    return fd;

err:
    errno = status;
    return -1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (sockfd < FILE_DESCRIPTOR_LOWER ||
        addr->sa_family != AF_INET)
    {
        init_originals();
        return original_bind(sockfd, addr, addrlen);
    }

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    QUIC_CREDENTIAL_CONFIG config = { 0 };
    QUIC_CERTIFICATE_FILE certfile;
    certfile.CertificateFile = "cert/server.cert";
    certfile.PrivateKeyFile = "cert/server.key";
    config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    config.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    config.CertificateFile = &certfile;
    
    if (QUIC_FAILED(status = MsQuic->ConfigurationLoadCredential(Configuration, &config)))
    {
        printf("QUIC: ConfigurationLoadCredential failed, 0x%x!\n", status);
        goto err; 
    }

    if (QUIC_FAILED(status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, (void*)&sockfd, &Listeners[LISTENER_IDX(sockfd)])))
    {
        printf("QUIC: ListenerOpen failed, 0x%x!\n", status);
        goto err;
    }
    printf("QUIC: Created listener()\n");
    QuicAddrSetFamily(&Addresses[LISTENER_IDX(sockfd)], QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&Addresses[LISTENER_IDX(sockfd)], ntohs(((struct sockaddr_in*)addr)->sin_port));

    printf("QUIC: Stored socket address and port\n");
    return 0;

err:
    errno = status;
    return -1;
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
        goto err;
    }
    QUIC_ADDR_STR addrStr = { 0 };
    if (QuicAddrToString(&Addresses[LISTENER_IDX(sockfd)], &addrStr))
        printf("QUIC: Start listening on %s\n", addrStr.Address);

    return 0;

err:
    errno = Status;
    MsQuic->ListenerClose(Listeners[LISTENER_IDX(sockfd)]);
    return -1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (sockfd < FILE_DESCRIPTOR_LOWER ||
        addr->sa_family != AF_INET)
    {
        init_originals();
        return original_connect(sockfd, addr, addrlen);
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    HQUIC Connection = NULL;
    QUIC_CREDENTIAL_CONFIG config = { 0 };

    config.Type = QUIC_CREDENTIAL_TYPE_NONE;
    config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    config.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &config)))
    {
        printf("QUIC: ConfigurationLoadCredential failed, 0x%x!\n", Status);
        goto err; 
    }


    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, (void*)&sockfd, &Connection)))
    {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto err;
    }

    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, address, INET_ADDRSTRLEN);
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_INET, address, ntohs(((struct sockaddr_in*)addr)->sin_port))))
    {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto err;
    }

    sleep(5);
    //while(!Connections[LISTENER_IDX(sockfd)]) sleep(1); //Simulate blocking call
    return 0;
err:
    errno = Status;
    if (QUIC_FAILED(Status) && Connection != NULL)
    {
        MsQuic->ConnectionClose(Connection);
    }
    return -1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (sockfd < FILE_DESCRIPTOR_LOWER ||
        !Listeners[LISTENER_IDX(sockfd)])
    {
        return original_accept(sockfd, addr, addrlen);
    }
    while(!Connections[LISTENER_IDX(sockfd)]) sleep(1); //Simulate blocking call
    return sockfd;
}
/*
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