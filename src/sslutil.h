#ifndef SUNK_SSLUTIL_H
#define SUNK_SSLUTIL_H
#include "openssl/ssl.h"
#include "openssl/err.h"
SSL_CTX *ssl_create_context();
void ssl_configure_context(SSL_CTX *ctx);
void create_global_contexts();
void free_global_contexts();
// Client contexts are shared
extern SSL_CTX *clientCtx;

typedef struct __tagSSLConnection
{
    int lastRet;
    int rawSocket;
    SSL *rawSsl;
    BIO *readBuffer;
    BIO *writeBuffer;
} SSLConnection;
SSLConnection *SSLConnection_New(SSL *ssl);
int SSLConnection_Accept(SSLConnection *conn);
int SSLConnection_Connect(SSLConnection *conn);
int SSLConnection_Read(SSLConnection *conn, void *buf, size_t num, size_t *readbytes);
int SSLConnection_Write(SSLConnection *conn, const void *buf, size_t num, size_t *written);
int SSLConnection_GetLastError(const SSLConnection *conn);
int SSLConnection_Shutdown(SSLConnection *conn);
void SSLConnection_Free(SSLConnection *conn);
#endif