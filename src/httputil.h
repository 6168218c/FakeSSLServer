#ifndef SUNK_HTTPUTIL_H
#define SUNK_HTTPUTIL_H
#include "shared.h"
#include <stdbool.h>
#include <openssl/ssl.h>
#define BUF_SIZE 8192
typedef void (*HeaderModifier)(BIO *target, const char *tagStart, const char *valueStart, int len);
typedef enum __tagHttpStreamState
{
    HTTP_STREAM_IDLE,
    HTTP_STREAM_HEADER,
    HTTP_STREAM_CONTENT
} HttpStreamState;
typedef enum __tagProxyResult
{
    PROXY_FATAL = -1,
    PROXY_FAIL = 0,
    PROXY_OK = 1
} ProxyResult;
typedef struct
{
    SSL *sslConnection;
    FILE *loggingFile;
    int errCode;
    HttpStreamState streamState;
    BIO *header;
    BIO *contentCache;
    int headerEndCount;
    bool isContentLength;
    bool isChunkedData;
    size_t bytesLeft;
} HttpState;
typedef struct
{
    fd_set fdread;
    char *origin;
    char buffer[BUF_SIZE];
    bool shouldShutdown;
    HttpState *victimState;
    HeaderModifier victimHeaderMod;
    HttpState *hostState;
    HeaderModifier hostHeaderMod;
} ProxySession;

ProxySession *ProxySession_New(SSL *ssl, char *loggingPath, int id, HeaderModifier victim, HeaderModifier host);
int ProxySession_ConnectToVictim(ProxySession *session);
char *ProxySession_RetrieveOrigin(ProxySession *session);
int ProxySession_ConnectToOrigin(ProxySession *session);
int ProxySession_WaitToRead(ProxySession *session);
int ProxySession_FlushHeaderCache(ProxySession *session, HttpState *source, HttpState *dest);
int ProxySession_FlushContentCache(ProxySession *session, HttpState *source, HttpState *dest);
ProxyResult ProxySession_HandleVictimTransmit(ProxySession *session);
ProxyResult ProxySession_HandleHostTransmit(ProxySession *session);
void ProxySession_Free(ProxySession *session);
#endif