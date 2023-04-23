#include "sslutil.h"

#define MIN(x, y) ((x < y) ? x : y)

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