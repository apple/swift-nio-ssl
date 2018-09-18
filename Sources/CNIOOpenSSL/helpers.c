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
#include <c_nio_openssl.h>
#include <stdio.h>
#include <pthread.h>
#include <assert.h>

/// This is a pointer to the BIO_METHOD structure for NIO's ByteBufferBIO.
///
/// This structure is always initialized at startup, and must be initialized in a
/// thread-safe manner. That means it should be guarded by some kind of pthread_once
/// setup behaviour, or a lock. For NIO, we use the initializeOpenSSL dance to do
/// this construction.
BIO_METHOD *CNIOOpenSSL_ByteBufferBIOMethod = NULL;

/// This is the type of the ByteBufferBIO created by Swift.
///
/// This type is used to create the BIO in Swift code. It can also be used to gate
/// initialization: if this is non-zero, we have already initialized ByteBufferBIOMethod
/// and can safely use it.
int CNIOOpenSSL_ByteBufferBIOType = 0;

static const char * const bio_name = "ByteBuffer BIO";

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
/// In the older OpenSSL's, we embed this structure statically into this compilation unit and
/// point at it. It begins nil'd out, as we want to be able to set the values from Swift code.
static BIO_METHOD byte_buffer_bio_method_actual = { 0 };
#endif

/// Initialize the `CNIOOpenSSL_ByteBufferBIOMethod` pointer with the values of
/// our specific ByteBuffer BIO type.
void CNIOOpenSSL_initByteBufferBIO(int (*bioWriteFunc)(void *, const char *, int),
                                   int (*bioReadFunc)(void *, char  *, int),
                                   int (*bioPutsFunc)(void *, const char *),
                                   int (*bioGetsFunc)(void *, char *, int),
                                   long (*bioCtrlFunc)(void *, int, long, void *),
                                   int (*bioCreateFunc)(void *),
                                   int (*bioDestroyFunc)(void *)) {
    assert(CNIOOpenSSL_ByteBufferBIOType == 0);

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    // In newer versions of OpenSSL we have BIO_get_new_index, but here we don't, so we
    // pick a "random" number between 128 (what OpenSSL calls BIO_TYPE_START), and
    // 256 (the beginning of the bitfield for BIO_TYPE_DESCRIPTOR). I've decided I
    // quite like the number 202, so let's use that.
    CNIOOpenSSL_ByteBufferBIOType = 202 | BIO_TYPE_SOURCE_SINK;
    byte_buffer_bio_method_actual.type = CNIOOpenSSL_ByteBufferBIOType;
    byte_buffer_bio_method_actual.name = bio_name;
    byte_buffer_bio_method_actual.bwrite = (int (*)(BIO *, const char *, int))bioWriteFunc;
    byte_buffer_bio_method_actual.bread = (int (*)(BIO *, char *, int))bioReadFunc;
    byte_buffer_bio_method_actual.bputs = (int (*)(BIO *, const char *))bioPutsFunc;
    byte_buffer_bio_method_actual.bgets = (int (*)(BIO *, char *, int))bioGetsFunc;
    byte_buffer_bio_method_actual.ctrl = (long (*)(BIO *, int, long, void *))bioCtrlFunc;
    byte_buffer_bio_method_actual.create = (int (*)(BIO *))bioCreateFunc;
    byte_buffer_bio_method_actual.destroy = (int (*)(BIO *))bioDestroyFunc;

    // Having initialized the BIO_METHOD, we can now publish the address to it.
    CNIOOpenSSL_ByteBufferBIOMethod = &byte_buffer_bio_method_actual;
#else
    CNIOOpenSSL_ByteBufferBIOType = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK;
    CNIOOpenSSL_ByteBufferBIOMethod = BIO_meth_new(CNIOOpenSSL_ByteBufferBIOType, bio_name);
    BIO_meth_set_write(CNIOOpenSSL_ByteBufferBIOMethod, (int (*)(BIO *, const char *, int))bioWriteFunc);
    BIO_meth_set_read(CNIOOpenSSL_ByteBufferBIOMethod, (int (*)(BIO *, char *, int))bioReadFunc);
    BIO_meth_set_puts(CNIOOpenSSL_ByteBufferBIOMethod, (int (*)(BIO *, const char *))bioPutsFunc);
    BIO_meth_set_gets(CNIOOpenSSL_ByteBufferBIOMethod, (int (*)(BIO *, char *, int))bioGetsFunc);
    BIO_meth_set_ctrl(CNIOOpenSSL_ByteBufferBIOMethod, (long (*)(BIO *, int, long, void *))bioCtrlFunc);
    BIO_meth_set_create(CNIOOpenSSL_ByteBufferBIOMethod, (int (*)(BIO *))bioCreateFunc);
    BIO_meth_set_destroy(CNIOOpenSSL_ByteBufferBIOMethod, (int (*)(BIO *))bioDestroyFunc);
#endif

    assert(CNIOOpenSSL_ByteBufferBIOType != 0);
}


/// This will store the locks we're using for the locking callbacks.
static pthread_mutex_t *locks = NULL;
static int lockCount = 0;


/// Our locking callback. It lives only in this compilation unit.
static void CNIOOpenSSL_locking_callback(int mode, int lockIndex, const char *file, int line) {
    if (lockIndex >= lockCount) {
        fprintf(stderr, "Invalid lock index %d, only have %d locks\n", lockIndex, lockCount);
        abort();
    }

    int rc;
    if (mode & CRYPTO_LOCK) {
        rc = pthread_mutex_lock(&locks[lockIndex]);
    } else {
        rc = pthread_mutex_unlock(&locks[lockIndex]);
    }

    if (rc != 0) {
        fprintf(stderr, "Failed to operate mutex: error %d, mode %d", rc, mode);
        abort();
    }
}


/// Our thread-id callback. Again, only in this compilation unit.
static unsigned long CNIOOpenSSL_thread_id_function(void) {
    return (unsigned long)pthread_self();
}


/// Initialize the locking callbacks.
static void CNIOOpenSSL_InitializeLockingCallbacks(void) {
    // The locking callbacks are only necessary on OpenSSL earlier than 1.1, or
    // libre.
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
    // Don't double-set the locking callbacks.
    if (CRYPTO_get_locking_callback() != NULL) {
        return;
    }

    lockCount = CRYPTO_num_locks();
    locks = malloc(lockCount * sizeof(typeof(locks[0])));

    for (int i = 0; i < lockCount; i++) {
        pthread_mutex_init(&locks[i], NULL);
    }

    CRYPTO_set_id_callback(CNIOOpenSSL_thread_id_function);
    CRYPTO_set_locking_callback(CNIOOpenSSL_locking_callback);
#endif
    return;
}


/// Initialize OpenSSL.
void CNIOOpenSSL_InitializeOpenSSL(void) {
    SSL_library_init();
    OPENSSL_add_all_algorithms_conf();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    CNIOOpenSSL_InitializeLockingCallbacks();
}

/// A no-op verify callback, for use from Swift.
int CNIOOpenSSL_noop_verify_callback(int preverify_ok, X509_STORE_CTX *context) {
    return preverify_ok;
}

/// A small helper to allow querying whether we were build against LibreSSL or not.
///
/// Returns 1 if we built against LibreSSL, 0 if we did not.
int CNIOOpenSSL_is_libressl(void) {
#if defined(LIBRESSL_VERSION_NUMBER)
    return 1;
#else
    return 0;
#endif
}

// This wrapper is used to erase the types required for this function. It's a bad
// thing to have to do, but until OpaquePointer gets better this is the only way to make
// this function work.
int CNIOOpenSSL_PKCS12_parse(void *p12, const char *pass, void **pkey, void **cert, void **ca) {
    return PKCS12_parse((PKCS12 *)p12, pass, (EVP_PKEY **)pkey, (X509 **)cert, (STACK_OF(X509) **)ca);
}
