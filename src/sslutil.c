#include "sslutil.h"

#define MIN(x, y) ((x < y) ? x : y)

SSL_CTX *clientCtx;

int ssl_alpn_configurer(SSL *ssl,
                        const unsigned char **out,
                        unsigned char *outlen,
                        const unsigned char *in,
                        unsigned int inlen,
                        void *arg)
{
    int protoStart = 0;
    while (protoStart < inlen)
    {
        int protoLen = in[protoStart];
        if (memcmp(in + protoStart + 1, "http/1.1", 8) == 0)
        {
            *out = in + protoStart + 1;
            *outlen = protoLen;
            return SSL_TLSEXT_ERR_OK;
        }
        protoStart += protoLen + 1;
    }
    return SSL_TLSEXT_ERR_ALERT_WARNING;
}

SSL_CTX *ssl_create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_alpn_select_cb(ctx, ssl_alpn_configurer, NULL);

    return ctx;
}

void ssl_configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void create_global_contexts()
{
    clientCtx = SSL_CTX_new(TLS_client_method());
}

void free_global_contexts()
{
    SSL_CTX_free(clientCtx);
}

SSLConnection *SSLConnection_New(SSL *ssl)
{
    SSLConnection *conn = malloc(sizeof(SSLConnection));
    memset(conn, 0, sizeof(SSLConnection));
    conn->rawSsl = ssl;
    conn->rawSocket = SSL_get_fd(ssl);
    conn->readBuffer = BIO_new(BIO_s_mem());
    conn->writeBuffer = BIO_new(BIO_s_mem());
    return conn;
}
int SSLConnection_Accept(SSLConnection *conn)
{
    conn->lastRet = SSL_accept(conn->rawSsl);
    if (conn->lastRet > 0 && !SSL_is_init_finished(conn->rawSsl))
    {
        // retry once
        conn->lastRet = SSL_do_handshake(conn->rawSsl);
    }
    return conn->lastRet;
}
int SSLConnection_Connect(SSLConnection *conn)
{
    conn->lastRet = SSL_connect(conn->rawSsl);
    if (conn->lastRet > 0 && !SSL_is_init_finished(conn->rawSsl))
    {
        // retry once
        conn->lastRet = SSL_do_handshake(conn->rawSsl);
    }
    return conn->lastRet;
}
int SSLConnection_Read(SSLConnection *conn, void *buf, size_t num, size_t *readbytes)
{
    return conn->lastRet = SSL_read_ex(conn->rawSsl, buf, num, readbytes);
}
int SSLConnection_Write(SSLConnection *conn, const void *buf, size_t num, size_t *written)
{
    return conn->lastRet = SSL_write_ex(conn->rawSsl, buf, num, written);
}
int SSLConnection_GetLastError(const SSLConnection *conn)
{
    return SSL_get_error(conn->rawSsl, conn->lastRet);
}
int SSLConnection_Shutdown(SSLConnection *conn)
{
    int err = SSLConnection_GetLastError(conn);
    if (err != SSL_ERROR_SSL && err != SSL_ERROR_SYSCALL)
    {
        return SSL_shutdown(conn->rawSsl);
    }
    return -1;
}
void SSLConnection_Free(SSLConnection *conn)
{
    if (conn->rawSsl)
        SSL_free(conn->rawSsl);
    if (conn->readBuffer)
        BIO_free(conn->readBuffer);
    if (conn->writeBuffer)
        BIO_free(conn->writeBuffer);
}