/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <CNIOBoringSSL_asn1.h>

#include <limits.h>

#include <CNIOBoringSSL_bio.h>
#include <CNIOBoringSSL_err.h>
#include <CNIOBoringSSL_mem.h>


void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x) {
  uint8_t *data;
  size_t len;
  // Historically, this function did not impose a limit in OpenSSL and is used
  // to read CRLs, so we leave this without an external bound.
  if (!BIO_read_asn1(in, &data, &len, INT_MAX)) {
    return NULL;
  }
  const uint8_t *ptr = data;
  void *ret = ASN1_item_d2i(reinterpret_cast<ASN1_VALUE **>(x), &ptr, len, it);
  OPENSSL_free(data);
  return ret;
}

void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x) {
  BIO *b = BIO_new_fp(in, BIO_NOCLOSE);
  if (b == NULL) {
    OPENSSL_PUT_ERROR(ASN1, ERR_R_BUF_LIB);
    return NULL;
  }
  void *ret = ASN1_item_d2i_bio(it, b, x);
  BIO_free(b);
  return ret;
}
