/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>

#include <CNIOBoringSSL_asn1t.h>
#include <CNIOBoringSSL_x509.h>

#include "internal.h"


ASN1_SEQUENCE(X509_VAL) = {
    ASN1_SIMPLE(X509_VAL, notBefore, ASN1_TIME),
    ASN1_SIMPLE(X509_VAL, notAfter, ASN1_TIME),
} ASN1_SEQUENCE_END(X509_VAL)

IMPLEMENT_ASN1_FUNCTIONS_const(X509_VAL)
