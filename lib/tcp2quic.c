#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include "tcp2quic.h"
#include "../include/msquic.h"
#include "../include/msquic_posix.h"
#include "ssl_secrets.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#define BUF_SIZE 1024
#define FILE_DESCRIPTOR_LOWER 10000
#define CONNECTIONS_FILE_DESCRIPTION_LOWER 20000
#define MAX_LISTENERS 128
#define MAX_CONNECTIONS 128
#define MAX_STREAMS 128
#define LISTENER_IDX(X)                  ((int)X - FILE_DESCRIPTOR_LOWER)
#define CONNECTION_IDX(X)                  ((int)X - CONNECTIONS_FILE_DESCRIPTION_LOWER)

QUIC_TLS_SECRETS ClientSecrets = {0};

const QUIC_API_TABLE* MsQuic   = NULL;
HQUIC Registration             = NULL;
HQUIC Configuration            = NULL;
static int fd_count            = FILE_DESCRIPTOR_LOWER;
HQUIC Listeners[MAX_LISTENERS] = { 0 };
QUIC_ADDR Addresses[MAX_LISTENERS] = { 0 };
HQUIC Connections[MAX_CONNECTIONS] = { 0 };
HQUIC Streams[MAX_STREAMS]         = { 0 };

uint8_t *read_buf;
size_t read_buf_length = 0;

struct QUIC_ctx {
    HQUIC *Connections;
    HQUIC *Streams;
    int fd;
    uint8_t *buf;
    size_t *size;
};

static int (*original_socket)(int, int, int) = NULL;
static int (*original_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*original_listen)(int, int) = NULL;
static int (*original_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*original_accept)(int, struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*original_read)(int, void *, size_t) = NULL;
static ssize_t (*original_write)(int, const void *, size_t) = NULL;
static ssize_t (*original_send)(int, const void*, size_t, int) = NULL;
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
        original_send    = dlsym(RTLD_NEXT, "send");
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
    Settings.IdleTimeoutMs = 10000;
    Settings.IsSet.IdleTimeoutMs = TRUE;
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
            int i;
            struct QUIC_ctx* qctx = (struct QUIC_ctx*)MsQuic->GetContext(Stream);
            for (i = 0; i < Event->RECEIVE.BufferCount; i++)
            {
                memcpy(qctx->buf, Event->RECEIVE.Buffers[i].Buffer, (size_t) Event->RECEIVE.Buffers[i].Length);
                qctx->buf[(size_t) Event->RECEIVE.Buffers[i].Length] = '\0';
                *qctx->size = (size_t) Event->RECEIVE.Buffers[i].Length;
            }
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
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)StreamCallback, ctx);
            struct QUIC_ctx* qctx = (struct QUIC_ctx*)MsQuic->GetContext(Connection);
            qctx->Streams[LISTENER_IDX(qctx->fd)] = Event->PEER_STREAM_STARTED.Stream;
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
            const char* SslKeyLogFile = getenv("SSLKEYLOGFILE");
            if (SslKeyLogFile != NULL)
            {
                WriteSslKeyLogFile(SslKeyLogFile, &ClientSecrets);
            }
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
            printf("[listn][%p] New connection\n", Listener);

            MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, ctx);
            Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
            struct QUIC_ctx* qctx = (struct QUIC_ctx*)MsQuic->GetContext(Listener);
            qctx->Connections[LISTENER_IDX(qctx->fd)] = Event->NEW_CONNECTION.Connection;
            break;
        
        default:
            break;
    }
    return Status;
}

int socket(int domain, int type, int protocol)
{
    init_originals();
    if (domain != AF_INET || type != SOCK_STREAM)
    {
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
    init_originals();
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

    struct QUIC_ctx *qctx = malloc(sizeof(struct QUIC_ctx));
    qctx->Connections = Connections;
    qctx->Streams = Streams;
    qctx->fd = sockfd;
    read_buf = malloc(BUF_SIZE);
    qctx->buf = read_buf;
    qctx->size = &read_buf_length;

    if (QUIC_FAILED(status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, (void*)qctx, &Listeners[LISTENER_IDX(sockfd)])))
    {
        printf("QUIC: ListenerOpen failed, 0x%x!\n", status);
        goto err;
    }
    printf("QUIC: Created listener\n");
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
    init_originals();
    if (!Listeners[LISTENER_IDX(sockfd)] ||
        QuicAddrGetFamily(&Addresses[LISTENER_IDX(sockfd)]) != AF_INET)
    {
        init_originals();
        return original_listen(sockfd, backlog);
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listeners[LISTENER_IDX(sockfd)], &Alpn, 1, &Addresses[LISTENER_IDX(sockfd)])))
    {
        printf("QUIC: ListenerStart failed, 0x%x!\n", Status);
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
    init_originals();
    if (sockfd < FILE_DESCRIPTOR_LOWER ||
        addr->sa_family != AF_INET)
    {
        init_originals();
        return original_connect(sockfd, addr, addrlen);
    }

    const char* SslKeyLogFile = getenv("SSLKEYLOGFILE");
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    HQUIC Connection = NULL;
    HQUIC Stream = NULL;
    QUIC_CREDENTIAL_CONFIG config = { 0 };

    config.Type = QUIC_CREDENTIAL_TYPE_NONE;
    config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    config.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &config)))
    {
        printf("QUIC: ConfigurationLoadCredential failed, 0x%x!\n", Status);
        goto err; 
    }

    struct QUIC_ctx *qctx = malloc(sizeof(struct QUIC_ctx));
    qctx->Connections = Connections;
    qctx->Streams = Streams;
    qctx->fd = sockfd;
    read_buf = malloc(BUF_SIZE);
    qctx->buf = read_buf;
    qctx->size = &read_buf_length;

    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &Connection)))
    {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto err;
    }

    if (SslKeyLogFile != NULL)
    {
        if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_TLS_SECRETS, sizeof(ClientSecrets), &ClientSecrets))) {
            printf("SetParam(QUIC_PARAM_CONN_TLS_SECRETS) failed, 0x%x!\n", Status);
            goto err;
        }
    }

    printf("[conn][%p] Connecting...\n", Connection);
    char address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, address, INET_ADDRSTRLEN);
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_INET, address, ntohs(((struct sockaddr_in*)addr)->sin_port))))
    {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto err;
    }

    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, StreamCallback, (void*)qctx, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        goto err;
    }

    if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        goto err;
    }

    Connections[LISTENER_IDX(sockfd)] = Connection;
    Streams[LISTENER_IDX(sockfd)] = Stream;

    sleep(1); //give some time for async connection

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
    init_originals();
    if (sockfd < FILE_DESCRIPTOR_LOWER ||
        !Listeners[LISTENER_IDX(sockfd)])
    {
        return original_accept(sockfd, addr, addrlen);
    }
    while(!Connections[LISTENER_IDX(sockfd)]) sleep(1); //Simulate blocking call
    return LISTENER_IDX(sockfd) + CONNECTIONS_FILE_DESCRIPTION_LOWER;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    init_originals();
    if (fd < FILE_DESCRIPTOR_LOWER)
    {
        return original_write(fd, buf, count);
    }
    int idx = -1;
    if (fd >= CONNECTIONS_FILE_DESCRIPTION_LOWER)
        idx = CONNECTION_IDX(fd);
    else
        idx = LISTENER_IDX(fd);
    
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint8_t* SendBufferRaw;
    SendBufferRaw = (uint8_t*)malloc(sizeof(QUIC_BUFFER) + count);
    if (SendBufferRaw == NULL) {
        printf("SendBuffer allocation failed!\n");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto err;
    }
    QUIC_BUFFER* SendBuffer;
    SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    memcpy(SendBuffer->Buffer, buf, count);
    SendBuffer->Length = (uint32_t) count;

    if (QUIC_FAILED(Status = MsQuic->StreamSend(Streams[idx], SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer)))
    {
        printf("StreamSend failed, 0x%x!\n", Status);
        goto err;
    }
    return count;

err:
    errno = Status;
    return -1;
}


ssize_t send(int sockfd, const void *buf, size_t length, int flags)
{
    init_originals();
    if (sockfd < FILE_DESCRIPTOR_LOWER)
    {
        return original_send(sockfd, buf, length, flags);
    }
    // Ignore flags
    return write(sockfd, buf, length);
}



ssize_t read(int fd, void *buf, size_t count)
{
    init_originals();
    if (fd < FILE_DESCRIPTOR_LOWER)
    {
        return original_read(fd, buf, count);
    }
    while (!read_buf_length) sleep(1); //block until we get some data
    int ret = read_buf_length;
    printf("QUIC: Read buff is %s\n", read_buf);
    memcpy(buf, read_buf, read_buf_length);
    memset(read_buf, 0, BUF_SIZE);
    read_buf_length = 0;
    return ret;
}

/*
int close(int fd)
{
    if (fd < FILE_DESCRIPTOR_LOWER)
    {
        return original_close(fd);
    }

    if (fd >= CONNECTIONS_FILE_DESCRIPTION_LOWER)
    {
        MsQuic->ConnectionClose(Connections[CONNECTION_IDX(fd)]);
    }

    MsQuic->ConnectionClose(Connections[LISTENER_IDX(fd)]);
    return 0;
}
*/