//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
// These are functions that shim over differences in different OpenSSL versions,
// which are best handled by using the C preprocessor.
#include <c_nio_openssl.h>

void CNIOOpenSSL_SSL_CTX_setAutoECDH(SSL_CTX *ctx) {
#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL && OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, 1, NULL);
#endif
}

int CNIOOpenSSL_SSL_set_tlsext_host_name(SSL *ssl, const char *name) {
    return SSL_set_tlsext_host_name(ssl, name);
}

const unsigned char *CNIOOpenSSL_ASN1_STRING_get0_data(ASN1_STRING *x) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
    return ASN1_STRING_data(x);
#else
    return ASN1_STRING_get0_data(x);
#endif
}

const SSL_METHOD *CNIOOpenSSL_TLS_Method(void) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    return SSLv23_method();
#else
    return TLS_method();
#endif
}

int CNIOOpenSSL_X509_up_ref(X509 *x) {
    // OpenSSL prior to 1.1 requires that we just mess about in the X509 structure. LibreSSL 2.7 brought in the
    // OpenSSL 1.1 API, so if we can we'll use that: otherwise we just mess about as with OpenSSL 1.0.
#if ((OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL))
    return CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
#else
    return X509_up_ref(x);
#endif
}

int CNIOOpenSSL_SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
    return SSL_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
#else
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, argl, argp, new_func, dup_func, free_func);
#endif
}

// MARK: Macro wrappers
// These are functions that rely on things declared in macros in OpenSSL, at least in
// some versions. The Swift compiler cannot expand C macros, so we need a file that
// can.
int CNIOOpenSSL_sk_GENERAL_NAME_num(STACK_OF(GENERAL_NAME) *x) {
    return sk_GENERAL_NAME_num(x);
}

const GENERAL_NAME *CNIOOpenSSL_sk_GENERAL_NAME_value(STACK_OF(GENERAL_NAME) *x, int idx) {
    return sk_GENERAL_NAME_value(x, idx);
}

int CNIOOpenSSL_sk_X509_num(STACK_OF(X509) *x) {
    return sk_X509_num(x);
}

const X509 *CNIOOpenSSL_sk_X509_value(STACK_OF(X509) *x, int idx) {
    return sk_X509_value(x, idx);
}

void CNIOOpenSSL_sk_X509_free(STACK_OF(X509) *x) {
    return sk_X509_free(x);
}

int CNIOOpenSSL_SSL_CTX_set_app_data(SSL_CTX *ctx, void *arg) {
    return SSL_CTX_set_app_data(ctx, arg);
}

void *CNIOOpenSSL_SSL_CTX_get_app_data(SSL_CTX *ctx) {
    return SSL_CTX_get_app_data(ctx);
}

long CNIOOpenSSL_SSL_CTX_set_mode(SSL_CTX *ctx, long mode) {
    return SSL_CTX_set_mode(ctx, mode);
}

long CNIOOpenSSL_SSL_CTX_set_options(SSL_CTX *ctx, long options) {
    return SSL_CTX_set_options(ctx, options);
}

int CNIOOpenSSL_SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str) {
#if (OPENSSL_VERSION_NUMBER < 0x10101000L) || defined(LIBRESSL_VERSION_NUMBER)
    return 1;
#else
    return SSL_CTX_set_ciphersuites(ctx, str);
#endif
}

void CNIOOpenSSL_OPENSSL_free(void *addr) {
    OPENSSL_free(addr);
}

int CNIOOpenSSL_X509_set_notBefore(X509 *x, const ASN1_TIME *tm) {
    return X509_set_notBefore(x, tm);
}

int CNIOOpenSSL_X509_set_notAfter(X509 *x, const ASN1_TIME *tm) {
    return X509_set_notAfter(x, tm);
}

unsigned long CNIOOpenSSL_OpenSSL_version_num(void) {
    return SSLeay();
}

int CNIOOpenSSL_SSL_CTX_set_alpn_protos(SSL_CTX *ctx,
                                        const unsigned char *protos,
                                        unsigned int protos_len) {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    return SSL_CTX_set_alpn_protos(ctx, protos, protos_len);
#else
    return 1;
#endif
}

void CNIOOpenSSL_SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                            CNIOOpenSSL_SSL_CTX_alpn_select_cb_func cb,
                                            void *arg) {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_CTX_set_alpn_select_cb(ctx, cb, arg);
#endif
}

void CNIOOpenSSL_SSL_get0_alpn_selected(const SSL *ssl,
                                        const unsigned char **data,
                                        unsigned int *len) {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_get0_alpn_selected(ssl, data, len);
#endif
}

int CNIOOpenSSL_BIO_get_init(BIO *bio) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    return bio->init;
#else
    return BIO_get_init(bio);
#endif
}

void CNIOOpenSSL_BIO_set_init(BIO *bio, int init) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    bio->init = init;
#else
    BIO_set_init(bio, init);
#endif
}

void *CNIOOpenSSL_BIO_get_data(BIO *bio) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    return bio->ptr;
#else
    return BIO_get_data(bio);
#endif
}

void CNIOOpenSSL_BIO_set_data(BIO *bio, void *ptr) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    bio->ptr = ptr;
#else
    BIO_set_data(bio, ptr);
#endif
}

int CNIOOpenSSL_BIO_get_shutdown(BIO *bio) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    return bio->shutdown;
#else
    return BIO_get_shutdown(bio);
#endif
}

void CNIOOpenSSL_BIO_set_shutdown(BIO *bio, int shut) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    bio->shutdown = shut;
#else
    BIO_set_shutdown(bio, shut);
#endif
}

void CNIOOpenSSL_BIO_clear_retry_flags(BIO *bio) {
    BIO_clear_retry_flags(bio);
}

void CNIOOpenSSL_BIO_set_retry_read(BIO *bio) {
    BIO_set_retry_read(bio);
}

int CNIOOpenSSL_BIO_up_ref(BIO *bio) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    CRYPTO_add(&bio->references, 1, CRYPTO_LOCK_BIO);
    return 1;
#else
    return BIO_up_ref(bio);
#endif
}

int CNIOOpenSSL_BIO_should_retry(BIO *bio) {
    return BIO_should_retry(bio);
}

int CNIOOpenSSL_BIO_should_read(BIO *bio) {
    return BIO_should_read(bio);
}

int CNIOOpenSSL_BIO_get_close(BIO *bio) {
    return BIO_get_close(bio);
}

int CNIOOpenSSL_BIO_set_close(BIO *bio, long flag) {
    return BIO_set_close(bio, flag);
}

long CNIOOpenSSL_BIO_get_mem_data(BIO *bio, char **dataPtr) {
    return BIO_get_mem_data(bio, dataPtr);
}
