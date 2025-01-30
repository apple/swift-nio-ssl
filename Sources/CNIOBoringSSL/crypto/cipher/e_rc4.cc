/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>

#include <CNIOBoringSSL_cipher.h>
#include <CNIOBoringSSL_nid.h>
#include <CNIOBoringSSL_rc4.h>

#include "../fipsmodule/cipher/internal.h"


static int rc4_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc) {
  RC4_KEY *rc4key = (RC4_KEY *)ctx->cipher_data;

  RC4_set_key(rc4key, EVP_CIPHER_CTX_key_length(ctx), key);
  return 1;
}

static int rc4_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                      size_t in_len) {
  RC4_KEY *rc4key = (RC4_KEY *)ctx->cipher_data;

  RC4(rc4key, in_len, in, out);
  return 1;
}

static const EVP_CIPHER rc4 = {
    /*nid=*/NID_rc4,
    /*block_size=*/1,
    /*key_len=*/16,
    /*iv_len=*/0,
    /*ctx_size=*/sizeof(RC4_KEY),
    /*flags=*/EVP_CIPH_VARIABLE_LENGTH,
    /*init=*/rc4_init_key,
    /*cipher=*/rc4_cipher,
    /*cleanup=*/nullptr,
    /*ctrl=*/nullptr,
};

const EVP_CIPHER *EVP_rc4(void) { return &rc4; }
