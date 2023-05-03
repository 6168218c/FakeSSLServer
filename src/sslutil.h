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
#endif