#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
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

void *handleRequest(void *sslreq);
void transferData(SSL *victim, SSL *host);
void modifiyVictimHeader(BIO *target, const char *tagStart, const char *valueStart, int len);
void exploitVictimData(char *buffer, int len);
void exploitHostData(char *buffer, int len);

int main(int argc, char **argv)
{
    int port = 27013;

    if (argc == 3)
    {
        if (strcmp(argv[1], "-p") == 0)
        {
            sscanf(argv[2], "%d", &port);
        }
    }
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
        SSL_set_fd(ssl, client);
        pthread_t thread;
        pthread_create(&thread, NULL, handleRequest, ssl);
        pthread_detach(thread);
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

void freeBios(BIO *header, BIO *contentCache, BIO *targetHeader)
{
    if (header)
        BIO_free(header);
    if (contentCache)
        BIO_free(contentCache);
    if (targetHeader)
        BIO_free(targetHeader);
}

int writeBioToSsl(BIO *bio, SSL *ssl, size_t *written)
{
    BUF_MEM *buf;
    size_t temp;
    BIO_get_mem_ptr(bio, &buf);
    if (written == NULL)
    {
        written = &temp;
    }
    return SSL_write_ex(ssl, buf->data, buf->length, written);
}

#define BUF_SIZE 8192

void *handleRequest(void *sslreq)
{
    SSL *ssl = sslreq;
    int client = SSL_get_fd(ssl);
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

    size_t readBytes = 0;
    BIO *headerBio = BIO_new(BIO_s_mem());
    BIO *contentCache = BIO_new(BIO_s_mem());
    char *endStr = "\r\n\r\n";
    int comparePos = 0;
    bool hasReadHeader = false;
    while (!hasReadHeader && (ret = SSL_read_ex(ssl, buffer, BUF_SIZE, &readBytes) >= 0))
    {
        if (readBytes > 0) // we should have read header
        {
            for (int i = 0; i < readBytes; i++)
            {
                if (buffer[i] != endStr[comparePos])
                {
                    if (comparePos != 0)
                        comparePos = 0; // reset
                    continue;
                }
                for (; buffer[i] == endStr[comparePos] && i < readBytes && comparePos < 4;
                     i++, comparePos++)
                    ;
                if (comparePos == 4) // we have found the end
                {
                    hasReadHeader = true;
                    BIO_write(headerBio, buffer, i); // i is past-end here, in other words, len
                    BIO_write(contentCache, buffer + i, readBytes - i);
                    break;
                }
                else
                {
                    // revert i
                    --i;
                }
            }
        }
        else
        {
            err = SSL_get_error(ssl, ret);
            if (err != SSL_ERROR_NONE && err != SSL_ERROR_ZERO_RETURN)
            {
                errCloseSSL(ssl, err);
                return NULL;
            }
        }
    }

    BIO *targetHeader = BIO_new(BIO_s_mem());
    char line[BUF_SIZE];
    int lineLen;

    struct hostent *remoteHost;
    bool foundHost = false;
    while (lineLen = BIO_gets(headerBio, line, BUF_SIZE))
    {
        if (memcmp(line, "\r\n\r\n", 4) == 0)
        {
            BIO_write(targetHeader, "\r\n\r\n", 4);
        }
        int start = 0;
        for (; line[start] != ' '; start++) // skip tag
            ;
        for (; line[start] == ' '; start++) // skip spaces
            ;
        if (memcmp(line, "Host", 4) == 0)
        {
            foundHost = true;
            int end = lineLen - 2;
            char *host = malloc(end + 1 - start);
            memset(host, 0, end + 1 - start);
            memcpy(host, line + start, end - start);
            remoteHost = gethostbyname(host);
            free(host);
            if (remoteHost == NULL) // or satisify some condition
            {
#if DEBUG
                remoteHost = gethostbyname("www.baidu.com");
                BIO_puts(targetHeader, "Host: www.baidu.com\r\n");
#endif
            }
            else
            {
                BIO_write(targetHeader, line, lineLen);
            }
        }
        else
        {
            modifiyVictimHeader(targetHeader, line, line + start, lineLen);
        }
    }
    BIO_free(headerBio);
    if (!foundHost)
    {
        freeBios(NULL, contentCache, targetHeader);
    }

    int serverSocket = 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr;
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
        freeBios(NULL, contentCache, targetHeader);
        return NULL;
    }
    if (connect(serverSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOGERROR(handleRequest, "Unable to bind");
        close(serverSocket);
        SSL_write(ssl, "Failed to connect to host!", 26);
        errCloseSSL(ssl, SSL_ERROR_NONE);
        freeBios(NULL, contentCache, targetHeader);
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
        freeBios(NULL, contentCache, targetHeader);
        return NULL;
    }

    ret = writeBioToSsl(targetHeader, subSsl, NULL);
    if (ret >= 0) // good connection
    {
        BIO_free(targetHeader);
        ret = writeBioToSsl(contentCache, subSsl, NULL);
        BIO_free(contentCache);
        transferData(ssl, subSsl);
    }

    printf("Connection #%lu ended!\n", pthread_self());

    SSL_shutdown(subSsl);
    SSL_free(subSsl);
    close(serverSocket);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
}

void modifiyVictimHeader(BIO *target, const char *tagStart, const char *valueStart, int len)
{
    int written = BIO_write(target, tagStart, len);
}

void transferData(SSL *victim, SSL *host)
{
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);
    int ret = 0;
    struct timeval timeout = {0, 1000};
    int victimSocket = SSL_get_fd(victim);
    int hostSocket = SSL_get_fd(host);
    char *endStr = "\r\n\r\n";
    int comparePos = 0;
    bool hasReadHeader = false;
    BIO *headerBio = BIO_new(BIO_s_mem());
    BIO *contentCache = BIO_new(BIO_s_mem());

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
        if (FD_ISSET(victimSocket, &fd_read))
        {
            ret = SSL_read_ex(victim, buffer, BUF_SIZE, &readBytes);
            if (ret > 0) // success
            {
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
                    LOGERROR(transferData, "Failed to read from victim!");
                }
                else
                {
                    // another dirty approach to detect closed
                    struct tcp_info info;
                    int len = sizeof info;
                    if (getsockopt(victimSocket, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&len) == 0)
                    {
                        if (info.tcpi_state == TCP_CLOSE_WAIT)
                        {
                            break;
                        }
                    }
                }
            }
        }
        if (FD_ISSET(hostSocket, &fd_read))
        {
            ret = SSL_read_ex(host, buffer, BUF_SIZE, &readBytes);
            if (ret > 0) // success
            {
                if (!hasReadHeader)
                {
                    for (int i = 0; i < readBytes; i++)
                    {
                        if (buffer[i] != endStr[comparePos])
                        {
                            if (comparePos != 0)
                                comparePos = 0; // reset
                            continue;
                        }
                        for (; buffer[i] == endStr[comparePos] && i < readBytes && comparePos < 4;
                             i++, comparePos++)
                            ;
                        if (comparePos == 4) // we have found the end
                        {
                            hasReadHeader = true;
                            BIO_write(headerBio, buffer, i); // i is past-end here, in other words, len
                            BIO_write(contentCache, buffer + i, readBytes - i);
                            break;
                        }
                        else
                        {
                            // revert i
                            --i;
                        }
                    }
                    if (hasReadHeader)
                    {
                        BIO *targetHeader = BIO_new(BIO_s_mem());
                        int lineLen;
                        char line[BUF_SIZE];
                        while (lineLen = BIO_gets(headerBio, line, BUF_SIZE))
                        {
                            if (memcmp(line, "\r\n\r\n", 4) == 0)
                            {
                                BIO_write(targetHeader, "\r\n\r\n", 4);
                            }
                            int start = 0;
                            for (; line[start] != ' '; start++) // skip tag
                                ;
                            for (; line[start] == ' '; start++) // skip spaces
                                ;
                            modifiyVictimHeader(targetHeader, line, line + start, lineLen);
                        }
                        writeBioToSsl(targetHeader, victim, &writtenBytes);
                        writeBioToSsl(contentCache, victim, &writtenBytes);
                        freeBios(headerBio, contentCache, targetHeader);
                    }
                }
                else
                {
                    ret = SSL_write_ex(victim, buffer, readBytes, &writtenBytes);
                    if (!ret || readBytes != writtenBytes) // error sending to victim
                    {
                        LOGERROR(transferData, "Failed to transmit to victim!");
                        break;
                    }
                }
            }
            else
            {
                int err = SSL_get_error(victim, ret);
                if (err != SSL_ERROR_ZERO_RETURN)
                {
                    LOGERROR(transferData, "Failed to read from Host!");
                }
                break;
            }
        }
    }
}