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
// Unfortunately, even in our brave BoringSSL world, we have "functions" that are
// macros too complex for the clang importer. This file handles them.
#include "CNIOBoringSSLShims.h"

X509_EXTENSION *CNIOBoringSSLShims_sk_X509_EXTENSION_value(const STACK_OF(X509_EXTENSION) *sk, size_t i) {
    return sk_X509_EXTENSION_value(sk, i);
}

size_t CNIOBoringSSLShims_sk_X509_EXTENSION_num(const STACK_OF(X509_EXTENSION) *sk) {
    return sk_X509_EXTENSION_num(sk);
}

void CNIOBoringSSLShims_sk_X509_EXTENSION_free(STACK_OF(X509_EXTENSION) *sk) {
    return sk_X509_EXTENSION_free(sk);
}

GENERAL_NAME *CNIOBoringSSLShims_sk_GENERAL_NAME_value(const STACK_OF(GENERAL_NAME) *sk, size_t i) {
    return sk_GENERAL_NAME_value(sk, i);
}

size_t CNIOBoringSSLShims_sk_GENERAL_NAME_num(const STACK_OF(GENERAL_NAME) *sk) {
    return sk_GENERAL_NAME_num(sk);
}

void *CNIOBoringSSLShims_SSL_CTX_get_app_data(const SSL_CTX *ctx) {
    return SSL_CTX_get_app_data(ctx);
}

int CNIOBoringSSLShims_SSL_CTX_set_app_data(SSL_CTX *ctx, void *data) {
    return SSL_CTX_set_app_data(ctx, data);
}

int CNIOBoringSSLShims_ERR_GET_LIB(uint32_t err) {
  return ERR_GET_LIB(err);
}

int CNIOBoringSSLShims_ERR_GET_REASON(uint32_t err) {
  return ERR_GET_REASON(err);
}

size_t CNIOBoringSSLShims_sk_X509_num(const STACK_OF(X509) *sk) {
    return sk_X509_num(sk);
}

X509 *CNIOBoringSSLShims_sk_X509_value(const STACK_OF(X509) *sk, size_t i) {
    return sk_X509_value(sk, i);
}

STACK_OF(X509) *CNIOBoringSSLShims_sk_X509_new_null(void) {
    return sk_X509_new_null();
}

void CNIOBoringSSLShims_sk_X509_pop_free(STACK_OF(X509) *sk, sk_X509_free_func free_func) {
    return sk_X509_pop_free(sk, free_func);
}

size_t CNIOBoringSSLShims_sk_X509_push(STACK_OF(X509) *sk, X509 *p) {
    return sk_X509_push(sk, p);
}

size_t CNIOBoringSSLShims_sk_CRYPTO_BUFFER_num(const STACK_OF(CRYPTO_BUFFER) *sk) {
    return sk_CRYPTO_BUFFER_num(sk);
}

CRYPTO_BUFFER *CNIOBoringSSLShims_sk_CRYPTO_BUFFER_value(const STACK_OF(CRYPTO_BUFFER) *sk, size_t i) {
    return sk_CRYPTO_BUFFER_value(sk, i);
}

size_t CNIOBoringSSLShims_sk_X509_NAME_num(const STACK_OF(X509_NAME) *sk) {
    return sk_X509_NAME_num(sk);
}

size_t CNIOBoringSSLShims_sk_SSL_CIPHER_num(const STACK_OF(SSL_CIPHER) *sk) {
    return sk_SSL_CIPHER_num(sk);
}

const SSL_CIPHER *CNIOBoringSSLShims_sk_SSL_CIPHER_value(const STACK_OF(SSL_CIPHER) *sk, size_t i) {
    return sk_SSL_CIPHER_value(sk, i);
}
