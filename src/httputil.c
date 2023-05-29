#include "httputil.h"
#include "sslutil.h"
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>
static int BIO_write_to_ssl(BIO *bio, SSLConnection *sslConnection, size_t *written)
{
    char *buf;
    size_t temp;
    size_t len = BIO_get_mem_data(bio, &buf);
    if (written == NULL)
    {
        written = &temp;
    }
    return SSLConnection_Write(sslConnection, buf, len, written);
}
static void BIO_dispose_used(BIO *bio, char *buffer, int buflen)
{
    char *mem;
    size_t len = BIO_get_mem_data(bio, &mem);
    OPENSSL_assert(len < buflen);
    BIO_read(bio, buffer, len);
    BIO_reset(bio);
    BIO_write(bio, buffer, len);
}
static bool HttpState_IsIdle(HttpState *state)
{
    return !(state->streamState | state->isChunkedData | state->isContentLength | state->bytesLeft);
}
static void HttpState_Free(HttpState *state)
{
    if (state->header)
    {
        BIO_free(state->header);
        state->header = NULL;
    }
    if (state->contentCache)
    {
        BIO_free(state->contentCache);
        state->contentCache = NULL;
    }
    if (state->sslConnection)
    {
        SSLConnection_Shutdown(state->sslConnection);
        SSLConnection_Free(state->sslConnection);
        state->sslConnection = NULL;
    }
    if (state->loggingFile)
    {
        fclose(state->loggingFile);
        state->loggingFile = NULL;
    }
}
static void HttpState_Reset(HttpState *state)
{
    state->streamState = state->isChunkedData = state->isContentLength = false;
    state->bytesLeft = 0;
}

ProxySession *ProxySession_New(SSL *ssl, char *loggingPath, int id, HeaderModifier victim, HeaderModifier host)
{
    ProxySession *session = malloc(sizeof(ProxySession));
    memset(session, 0, sizeof(ProxySession));
    FD_ZERO(&session->fdread);

    char fName[256];

    session->victimState = malloc(sizeof(HttpState));
    memset(session->victimState, 0, sizeof(HttpState));
    session->victimState->sslConnection = SSLConnection_New(ssl);
    session->victimState->header = BIO_new(BIO_s_mem());
    session->victimState->contentCache = BIO_new(BIO_s_mem());

    sprintf(fName, "%s/connection-%d.request", loggingPath, id);
    session->victimState->loggingFile = fopen(fName, "w");

    session->hostState = malloc(sizeof(HttpState));
    memset(session->hostState, 0, sizeof(HttpState));

    sprintf(fName, "%s/connection-%d.response", loggingPath, id);
    session->hostState->loggingFile = fopen(fName, "w");

    session->victimHeaderMod = victim;
    session->hostHeaderMod = host;
    return session;
}
int ProxySession_ConnectToVictim(ProxySession *session)
{
    int ret;
    if (ret = SSLConnection_Accept(session->victimState->sslConnection) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}
char *ProxySession_RetrieveOrigin(ProxySession *session)
{
    int ret;
    size_t readBytes;
    HttpState *state = session->victimState;
    char *buffer = session->buffer;
    state->streamState = HTTP_STREAM_HEADER;
    while (state->streamState == HTTP_STREAM_HEADER && (ret = SSLConnection_Read(state->sslConnection, buffer, BUF_SIZE, &readBytes) >= 0))
    {
        if (ret == 0)
        {
            if (SSLConnection_GetLastError(state->sslConnection) == SSL_ERROR_WANT_READ || SSLConnection_GetLastError(state->sslConnection) == SSL_ERROR_WANT_WRITE)
                continue;
        }
        if (readBytes > 0) // we should have read header
        {
            if (state->loggingFile)
            {
                fwrite(buffer, 1, readBytes, state->loggingFile);
            }
            for (int i = 0; i < readBytes; i++)
            {
                if (buffer[i] != (state->headerEndCount % 2 ? '\n' : '\r'))
                {
                    if (state->headerEndCount != 0)
                        state->headerEndCount = 0; // reset
                    continue;
                }
                for (; buffer[i] == (state->headerEndCount % 2 ? '\n' : '\r') && i < readBytes && state->headerEndCount < 4;
                     i++, state->headerEndCount++)
                    ;
                if (state->headerEndCount == 4) // we have found the end
                {
                    state->streamState = HTTP_STREAM_CONTENT;
                    BIO_write(state->header, buffer, i); // i is past-end here, in other words, len
                    BIO_write(state->contentCache, buffer + i, readBytes - i);
                    break;
                }
                else
                {
                    // revert i
                    --i;
                }
            }
            if (state->streamState == HTTP_STREAM_HEADER)
            {
                BIO_write(state->header, buffer, readBytes);
            }
        }
        else
        {
            int err = SSLConnection_GetLastError(state->sslConnection);
            if (err != SSL_ERROR_NONE && err != SSL_ERROR_ZERO_RETURN)
            {
                return NULL;
            }
        }
    }

    int lineLen;
    if (SSL_get_servername_type(state->sslConnection->rawSsl) == TLSEXT_NAMETYPE_host_name)
    {
        // use SNI
        const char *servername = SSL_get_servername(state->sslConnection->rawSsl, TLSEXT_NAMETYPE_host_name);
        if (servername)
        {
            int nameLen = strlen(servername);
            session->origin = malloc(nameLen + 1);
            memset(session->origin, 0, nameLen + 1);
            strcpy(session->origin, servername);
        }
#ifdef DEBUG_REDIRECT
        else
        {
            session->origin = malloc(15);
            memset(session->origin, 0, 15);
            strcpy(session->origin, "www.baidu.com");
        }
#endif
    }
    BIO *headerBio = state->header;
    BIO *targetHeader = BIO_new(BIO_s_mem());
    while (lineLen = BIO_gets(headerBio, session->buffer, BUF_SIZE))
    {
        if (memcmp(session->buffer, "\r\n", 2) == 0) // empty line
        {
            BIO_write(targetHeader, "\r\n", 2);
            break;
        }
        int start = 0;
        for (; session->buffer[start] != ' '; start++) // skip tag
            ;
        for (; session->buffer[start] == ' '; start++) // skip spaces
            ;
        if (!session->origin && (memcmp(session->buffer, "Host", 4) == 0))
        {
            int end = lineLen - 2;
            session->origin = malloc(end + 1 - start);
            memset(session->origin, 0, end + 1 - start);
            memcpy(session->origin, session->buffer + start, end - start);
#ifdef DEBUG_REDIRECT
            struct hostent *remoteHost = gethostbyname(session->origin);
            if (remoteHost == NULL)
            {
                remoteHost = gethostbyname("www.baidu.com");
                free(session->origin);
                session->origin = malloc(15);
                memset(session->origin, 0, 15);
                strcpy(session->origin, "www.baidu.com");
                BIO_puts(targetHeader, "Host: www.baidu.com\r\n");
            }
            else
#endif
                BIO_puts(targetHeader, session->buffer);
        }
        else if (memcmp(session->buffer, "Content-Length", 14) == 0)
        {
            state->isContentLength = true;
            sscanf(session->buffer + start, "%d", &state->bytesLeft);
            BIO_puts(targetHeader, session->buffer);
        }
        else if (memcmp(session->buffer, "Transfer-Encoding", 17) == 0)
        {
            if (strstr(session->buffer, "chunked"))
            {
                state->isChunkedData = true;
            }
            BIO_puts(targetHeader, session->buffer);
        }
        else if (session->victimHeaderMod)
        {
            session->victimHeaderMod(targetHeader, session->buffer, session->buffer + start, lineLen);
        }
    }
    state->header = targetHeader;
    BIO_free(headerBio);

    return session->origin;
}
int ProxySession_ConnectToOrigin(ProxySession *session)
{
    OPENSSL_assert(session->origin);
    struct hostent *remoteHost = gethostbyname(session->origin);
    if (remoteHost == NULL || remoteHost->h_addrtype != AF_INET || remoteHost->h_addr_list[0] == 0)
    {
        LOGERROR(ProxySession_ConnectToOrigin, "Failed to resolve host!");
        return false;
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = *(u_int32_t *)remoteHost->h_addr_list[0];
    int serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket < 0)
    {
        LOGERROR(ProxySession_ConnectToOrigin, "Error creating host socket!");
        return false;
    }
    if (connect(serverSocket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOGERROR(ProxySession_ConnectToOrigin, "Unable to connect to host");
        close(serverSocket);
        return false;
    }
    HttpState *state = session->hostState;
    SSL *serverSSL = SSL_new(clientCtx);
    SSL_set_fd(serverSSL, serverSocket);
    state->sslConnection = SSLConnection_New(serverSSL);
    if (SSLConnection_Connect(state->sslConnection) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    state->header = BIO_new(BIO_s_mem());
    state->contentCache = BIO_new(BIO_s_mem());

    // Now we have established connection, we should send header to host
    return ProxySession_FlushHeaderCache(session, session->victimState, session->hostState);
}
int ProxySession_FlushHeaderCache(ProxySession *session, HttpState *source, HttpState *dest)
{
    OPENSSL_assert(source->streamState == HTTP_STREAM_CONTENT); // have completed reading header
    char *method;
    int len = BIO_get_mem_data(source->header, &method);
    int ret;
    size_t writtenBytes;
    if (memcmp(method, "GET", 3) == 0) // Get
    {
        // transmit it, and mark as complete
        if (ret = BIO_write_to_ssl(source->header, dest->sslConnection, &writtenBytes) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
        BIO_reset(source->header);
        HttpState_Reset(source); // Connection complete
    }
    else
    {
        // transmit it, and mark as complete
        if (ret = BIO_write_to_ssl(source->header, dest->sslConnection, &writtenBytes) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
        BIO_reset(source->header);
    }
    return true;
}
int ProxySession_FlushContentCache(ProxySession *session, HttpState *source, HttpState *dest)
{
    OPENSSL_assert(source->streamState == HTTP_STREAM_CONTENT);
    if (source->isChunkedData)
    {
        while (true)
        {
            int bioStart = BIO_tell(source->contentCache);
            if (source->bytesLeft == 0) // completed a chunk
            {
                const char *buf;
                int total = BIO_get_mem_data(source->contentCache, &buf);
                BIO *currContent = BIO_new_mem_buf(buf, total - bioStart);
                int lineLen;
                int nextChunkLen = -1;
                while (lineLen = BIO_gets(currContent, session->buffer, BUF_SIZE) > 0)
                {
                    if (memcmp(session->buffer, "\r\n", 2) != 0) // not an empty line
                    {
                        sscanf(session->buffer, "%x", &nextChunkLen);
                        break;
                    }
                }
                if (nextChunkLen < 0) // not any chunk starts
                {
                    // do not flush, we should try again to see if any lineLengths
                    BIO_free(currContent);
                    // we need new data
                    break;
                }
                else if (nextChunkLen == 0) // chunk size 0,ending communication
                {
                    // however,we should also not flush if next line is not pure line end
                    lineLen = BIO_gets(currContent, session->buffer, BUF_SIZE);
                    if (lineLen == 2 && memcmp(session->buffer, "\r\n", 2) == 0) // really lineEnd
                    {
                        // flush all content
                        // reset to start first
                        BIO_free(currContent);
                        if (BIO_write_to_ssl(source->contentCache, dest->sslConnection, NULL) <= 0)
                        {
                            ERR_print_errors_fp(stderr);
                            return false;
                        }
                        BIO_reset(source->contentCache);
                        HttpState_Reset(source);
                        // Connction complete
                        break;
                    }
                    else
                    {
                        BIO_free(currContent);
                        // we need new data
                        break;
                    }
                }
                else
                {
                    source->bytesLeft = nextChunkLen;
                    int curLen = BIO_tell(currContent);
                    BIO_free(currContent);
                    BIO_read(source->contentCache, session->buffer, curLen);
                    size_t writtenBytes;
                    if (SSLConnection_Write(dest->sslConnection, session->buffer, curLen, &writtenBytes) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        return false;
                    }
                    // in the above steps we send the prepending data
                    // now we should send the actual chunk data
                    continue;
                }
            }
            else
            {
                char *buf;
                int ret;
                size_t writtenBytes;
                size_t available = BIO_get_mem_data(source->contentCache, &buf);
                if (source->bytesLeft < available)
                {
                    BIO_read(source->contentCache, session->buffer, source->bytesLeft);
                    if (ret = SSLConnection_Write(dest->sslConnection, session->buffer, source->bytesLeft, &writtenBytes) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        return false;
                    }
                    source->bytesLeft = 0;
                    BIO_dispose_used(source->contentCache, session->buffer, BUF_SIZE);
                    continue;
                }
                else
                {
                    if (ret = SSLConnection_Write(dest->sslConnection, buf, available, &writtenBytes) <= 0)
                    {
                        ERR_print_errors_fp(stderr);
                        return false;
                    }
                    BIO_reset(source->contentCache);
                    source->bytesLeft -= available;
                    // we need new data
                    break;
                }
            }
        }
        // BIO_dispose_used(source->contentCache, session->buffer, BUF_SIZE);
    }
    else if (source->isContentLength)
    {
        OPENSSL_assert(source->bytesLeft >= 0);
        size_t writtenBytes;
        int ret;
        if (ret = BIO_write_to_ssl(source->contentCache, dest->sslConnection, &writtenBytes) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
        BIO_reset(source->contentCache);
        source->bytesLeft -= writtenBytes;
        if (source->bytesLeft == 0)
        {
            // Connection complete
            HttpState_Reset(source);
        }
    }
    else // Connection:Close
    {
        // just write it already
        int ret;
        if (ret = BIO_write_to_ssl(source->contentCache, dest->sslConnection, NULL) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
        BIO_reset(source->contentCache);
    }
    return true;
}
int ProxySession_WaitToRead(ProxySession *session)
{
    if (session->shouldShutdown)
    {
        return 0;
    }
    struct timeval timeout = {0, 1000000};
    FD_ZERO(&session->fdread);
    int victimSocket = session->victimState->sslConnection->rawSocket;
    int hostSocket = session->hostState->sslConnection->rawSocket;
    FD_SET(victimSocket, &session->fdread);
    FD_SET(hostSocket, &session->fdread);
    int max = victimSocket > hostSocket ? victimSocket + 1 : hostSocket + 1;
    return select(max, &session->fdread, NULL, NULL, &timeout);
}
HttpStreamState ProxySession_RetrieveHeader(ProxySession *session, HttpState *state, char *buffer, int len)
{
    if (state->streamState == HTTP_STREAM_HEADER)
    {
        for (int i = 0; i < len; i++)
        {
            if (buffer[i] != (state->headerEndCount % 2 ? '\n' : '\r'))
            {
                if (state->headerEndCount != 0)
                    state->headerEndCount = 0; // reset
                continue;
            }
            for (; buffer[i] == (state->headerEndCount % 2 ? '\n' : '\r') && i < len && state->headerEndCount < 4;
                 i++, state->headerEndCount++)
                ;
            if (state->headerEndCount == 4) // we have found the end
            {
                state->streamState = HTTP_STREAM_CONTENT;
                BIO_write(state->header, buffer, i); // i is past-end here, in other words, len
                BIO_write(state->contentCache, buffer + i, len - i);
                break;
            }
            else
            {
                // revert i
                --i;
            }
        }
        if (state->streamState == HTTP_STREAM_HEADER)
        {
            BIO_write(state->header, buffer, len);
        }
    }
    else
    {
        // do nothing
    }
    return state->streamState;
}
int ProxySession_RetrieveContent(ProxySession *session, HttpState *state, char *buffer, int len)
{
    OPENSSL_assert(state->streamState == HTTP_STREAM_CONTENT);
    return BIO_write(state->contentCache, buffer, len);
}
void ProxySession_ModifyHeader(ProxySession *session, HttpState *state, HeaderModifier headerMod)
{
    OPENSSL_assert(state->streamState == HTTP_STREAM_CONTENT);
    if (state->streamState == HTTP_STREAM_CONTENT)
    {
        char *buf;
        int l = BIO_get_mem_data(state->header, &buf);
        BIO *targetHeader = BIO_new(BIO_s_mem());
        int lineLen;
        while (lineLen = BIO_gets(state->header, session->buffer, BUF_SIZE))
        {
            if (memcmp(session->buffer, "\r\n", 2) == 0)
            {
                BIO_write(targetHeader, "\r\n", 2);
                break;
            }
            int start = 0;
            for (; session->buffer[start] != ' '; start++) // skip tag
                ;
            for (; session->buffer[start] == ' '; start++) // skip spaces
                ;
#ifdef DEBUG_REDIRECT
            if (memcmp(session->buffer, "Host", 4) == 0) // host
            {
                sprintf(session->buffer, "Host: %s\r\n", session->origin);
                BIO_puts(targetHeader, session->buffer);
            }
            else if (memcmp(session->buffer, "Referer", 7) == 0)
            {
                // skip
                BIO_puts(targetHeader, "Referer: https://www.baidu.com/\r\n");
            }
            else
#endif
                if (memcmp(session->buffer, "Content-Length", 14) == 0)
            {
                state->isContentLength = true;
                sscanf(session->buffer + start, "%d", &state->bytesLeft);
                BIO_puts(targetHeader, session->buffer);
            }
            else if (memcmp(session->buffer, "Transfer-Encoding", 17) == 0)
            {
                if (strstr(session->buffer, "chunked"))
                {
                    state->isChunkedData = true;
                }
                BIO_puts(targetHeader, session->buffer);
            }
            else if (headerMod)
                headerMod(targetHeader, session->buffer, session->buffer + start, lineLen);
        }
        BIO_free(state->header);
        l = BIO_get_mem_data(targetHeader, &buf);
        state->header = targetHeader;
    }
}
ProxyResult ProxySession_HandleTransmit(ProxySession *session, HttpState *source, HttpState *dest, HeaderModifier sourceMod, FILE *logFile)
{
    int socket = source->sslConnection->rawSocket;
    if (!FD_ISSET(socket, &session->fdread))
    {
        return PROXY_OK;
    }
    int ret;
    size_t readBytes;
    if (ret = SSLConnection_Read(source->sslConnection, session->buffer, BUF_SIZE, &readBytes) > 0)
    {
        if (readBytes == 0)
        {
            struct tcp_info info;
            int len = sizeof info;
            if (getsockopt(socket, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&len) == 0)
            {
                if (info.tcpi_state == TCP_CLOSE_WAIT)
                {
                    session->shouldShutdown = true;
                    return PROXY_FAIL;
                }
            }
        }
        if (logFile)
        {
            fwrite(session->buffer, 1, readBytes, logFile);
        }
        if (HttpState_IsIdle(source))
        {
            source->streamState = HTTP_STREAM_HEADER; // switch state
            if (ProxySession_RetrieveHeader(session, source, session->buffer, readBytes) == HTTP_STREAM_CONTENT)
            {
                // header complete
                ProxySession_ModifyHeader(session, source, sourceMod);
                ProxySession_FlushHeaderCache(session, source, dest);
                if (source->streamState != HTTP_STREAM_IDLE) // incase we sent 'GET'
                    ProxySession_FlushContentCache(session, source, dest);
            }
        }
        else if (source->streamState == HTTP_STREAM_HEADER)
        {
            if (ProxySession_RetrieveHeader(session, source, session->buffer, readBytes) == HTTP_STREAM_CONTENT)
            {
                // header complete
                ProxySession_ModifyHeader(session, source, sourceMod);
                ProxySession_FlushHeaderCache(session, source, dest);
                if (source->streamState != HTTP_STREAM_IDLE) // incase we sent 'GET'
                    ProxySession_FlushContentCache(session, source, dest);
            }
        }
        else
        {
            ProxySession_RetrieveContent(session, source, session->buffer, readBytes);
            ProxySession_FlushContentCache(session, source, dest);
        }
    }
    else
    {
        ERR_print_errors_fp(stderr);
        int err = SSLConnection_GetLastError(source->sslConnection);
        if (err == SSL_ERROR_NONE || err == SSL_ERROR_ZERO_RETURN)
        {
            session->shouldShutdown = true;
            return PROXY_FAIL;
        }
        return PROXY_FATAL;
    }
    return true;
}
ProxyResult ProxySession_HandleVictimTransmit(ProxySession *session)
{
    HttpState *source = session->victimState;
    HttpState *dest = session->hostState;
    HeaderModifier sourceMod = session->victimHeaderMod;
    return ProxySession_HandleTransmit(session, source, dest, sourceMod, source->loggingFile);
}
ProxyResult ProxySession_HandleHostTransmit(ProxySession *session)
{
    HttpState *source = session->hostState;
    HttpState *dest = session->victimState;
    HeaderModifier sourceMod = session->hostHeaderMod;
    return ProxySession_HandleTransmit(session, source, dest, sourceMod, source->loggingFile);
}
void ProxySession_Free(ProxySession *session)
{
    free(session->origin);
    session->origin = NULL;
    HttpState_Free(session->victimState);
    session->victimState = NULL;
    HttpState_Free(session->hostState);
    session->hostState = NULL;
}