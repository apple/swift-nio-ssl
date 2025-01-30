/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <CNIOBoringSSL_cipher.h>

#include <string.h>

#include <CNIOBoringSSL_nid.h>

#include "../fipsmodule/cipher/internal.h"
#include "../internal.h"


static int null_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                         const uint8_t *iv, int enc) {
  return 1;
}

static int null_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                       size_t in_len) {
  if (in != out) {
    OPENSSL_memcpy(out, in, in_len);
  }
  return 1;
}

static const EVP_CIPHER n_cipher = {
    /*nid=*/NID_undef,
    /*block_size=*/1,
    /*key_len=*/0,
    /*iv_len=*/0,
    /*ctx_size=*/0,
    /*flags=*/0,
    /*init=*/null_init_key,
    /*cipher=*/null_cipher,
    /*cleanup=*/nullptr,
    /*ctrl=*/nullptr,
};

const EVP_CIPHER *EVP_enc_null(void) { return &n_cipher; }
