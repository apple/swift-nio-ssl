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
#ifndef C_NIO_BORINGSSL_SHIMS_H
#define C_NIO_BORINGSSL_SHIMS_H

// This is for instances when `swift package generate-xcodeproj` is used as CNIOBoringSSL
// is treated as a framework and requires the framework's name as a prefix.
#if __has_include(<CNIOBoringSSL/CNIOBoringSSL.h>)
#include <CNIOBoringSSL/CNIOBoringSSL.h>
#else
#include "CNIOBoringSSL.h"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

X509_EXTENSION *CNIOBoringSSLShims_sk_X509_EXTENSION_value(const STACK_OF(X509_EXTENSION) *sk, size_t i);
size_t CNIOBoringSSLShims_sk_X509_EXTENSION_num(const STACK_OF(X509_EXTENSION) *sk);
void CNIOBoringSSLShims_sk_X509_EXTENSION_free(STACK_OF(X509_EXTENSION) *sk);

GENERAL_NAME *CNIOBoringSSLShims_sk_GENERAL_NAME_value(const STACK_OF(GENERAL_NAME) *sk, size_t i);
size_t CNIOBoringSSLShims_sk_GENERAL_NAME_num(const STACK_OF(GENERAL_NAME) *sk);

void *CNIOBoringSSLShims_SSL_CTX_get_app_data(const SSL_CTX *ctx);
int CNIOBoringSSLShims_SSL_CTX_set_app_data(SSL_CTX *ctx, void *data);

int CNIOBoringSSLShims_ERR_GET_LIB(uint32_t err);
int CNIOBoringSSLShims_ERR_GET_REASON(uint32_t err);

size_t CNIOBoringSSLShims_sk_X509_num(const STACK_OF(X509) *sk);
X509 *CNIOBoringSSLShims_sk_X509_value(const STACK_OF(X509) *sk, size_t i);
STACK_OF(X509) *CNIOBoringSSLShims_sk_X509_new_null(void);
void CNIOBoringSSLShims_sk_X509_pop_free(STACK_OF(X509) *sk, sk_X509_free_func free_func);
size_t CNIOBoringSSLShims_sk_X509_push(STACK_OF(X509) *sk, X509 *p);

size_t CNIOBoringSSLShims_sk_CRYPTO_BUFFER_num(const STACK_OF(CRYPTO_BUFFER) *sk);
CRYPTO_BUFFER *CNIOBoringSSLShims_sk_CRYPTO_BUFFER_value(const STACK_OF(CRYPTO_BUFFER) *sk, size_t i);

size_t CNIOBoringSSLShims_sk_X509_NAME_num(const STACK_OF(X509_NAME) *sk);

size_t CNIOBoringSSLShims_sk_SSL_CIPHER_num(const STACK_OF(SSL_CIPHER) *sk);
const SSL_CIPHER *CNIOBoringSSLShims_sk_SSL_CIPHER_value(const STACK_OF(SSL_CIPHER) *sk, size_t i);

#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // C_NIO_BORINGSSL_SHIMS_H
