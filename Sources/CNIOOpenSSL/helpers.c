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
#include <assert.h>
#include <openssl/bio.h>

/// This is a pointer to the BIO_METHOD structure for NIO's ByteBufferBIO.
///
/// This structure is always initialized at startup, and must be initialized in a
/// thread-safe manner. That means it should be guarded by some kind of pthread_once
/// setup behaviour, or a lock. For NIO, we use the initializeOpenSSL dance to do
/// this construction.
const BIO_METHOD *CNIOOpenSSL_ByteBufferBIOMethod = NULL;

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
void CNIOOpenSSL_initByteBufferBIO(int (*bioWriteFunc)(BIO *, const char *, int),
                                   int (*bioReadFunc)(BIO *, char  *, int),
                                   int (*bioPutsFunc)(BIO *, const char *),
                                   int (*bioGetsFunc)(BIO *, char *, int),
                                   long (*bioCtrlFunc)(BIO *, int, long, void *),
                                   int (*bioCreateFunc)(BIO *),
                                   int (*bioDestroyFunc)(BIO *)) {
    assert(CNIOOpenSSL_ByteBufferBIOType == 0);

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    // In newer versions of OpenSSL we have BIO_get_new_index, but here we don't, so we
    // pick a "random" number between 128 (what OpenSSL calls BIO_TYPE_START), and
    // 256 (the beginning of the bitfield for BIO_TYPE_DESCRIPTOR). I've decided I
    // quite like the number 202, so let's use that.
    CNIOOpenSSL_ByteBufferBIOType = 202 | BIO_TYPE_SOURCE_SINK;
    byte_buffer_bio_method_actual.type = CNIOOpenSSL_ByteBufferBIOType;
    byte_buffer_bio_method_actual.name = bio_name;
    byte_buffer_bio_method_actual.bwrite = bioWriteFunc;
    byte_buffer_bio_method_actual.bread = bioReadFunc;
    byte_buffer_bio_method_actual.bputs = bioPutsFunc;
    byte_buffer_bio_method_actual.bgets = bioGetsFunc;
    byte_buffer_bio_method_actual.ctrl = bioCtrlFunc;
    byte_buffer_bio_method_actual.create = bioCreateFunc;
    byte_buffer_bio_method_actual.destroy = bioDestroyFunc;

    // Having initialized the BIO_METHOD, we can now publish the address to it.
    CNIOOpenSSL_ByteBufferBIOMethod = &byte_buffer_bio_method_actual;
#else
    CNIOOpenSSL_ByteBufferBIOType = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK;
    CNIOOpenSSL_ByteBufferBIOMethod = BIO_meth_new(CNIOOpenSSL_ByteBufferBIOType, bio_name);
    BIO_meth_set_write(CNIOOpenSSL_ByteBufferBIOMethod, bioWriteFunc);
    BIO_meth_set_read(CNIOOpenSSL_ByteBufferBIOMethod, bioReadFunc);
    BIO_meth_set_puts(CNIOOpenSSL_ByteBufferBIOMethod, bioPutsFunc);
    BIO_meth_set_gets(CNIOOpenSSL_ByteBufferBIOMethod, bioGetsFunc);
    BIO_meth_set_ctrl(CNIOOpenSSL_ByteBufferBIOMethod, bioCtrlFunc);
    BIO_meth_set_create(CNIOOpenSSL_ByteBufferBIOMethod, bioCreateFunc);
    BIO_meth_set_destroy(CNIOOpenSSL_ByteBufferBIOMethod, bioDestroyFunc);
#endif

    assert(CNIOOpenSSL_ByteBufferBIOType != 0);
}
