/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <CNIOBoringSSL_cipher.h>

#include <assert.h>

#include <CNIOBoringSSL_digest.h>
#include <CNIOBoringSSL_mem.h>


#define PKCS5_SALT_LEN 8

int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
                   const uint8_t *salt, const uint8_t *data, size_t data_len,
                   unsigned count, uint8_t *key, uint8_t *iv) {
  EVP_MD_CTX c;
  uint8_t md_buf[EVP_MAX_MD_SIZE];
  unsigned addmd = 0;
  unsigned mds = 0, i;
  int rv = 0;

  unsigned nkey = EVP_CIPHER_key_length(type);
  unsigned niv = EVP_CIPHER_iv_length(type);

  assert(nkey <= EVP_MAX_KEY_LENGTH);
  assert(niv <= EVP_MAX_IV_LENGTH);

  if (data == NULL) {
    return nkey;
  }

  EVP_MD_CTX_init(&c);
  for (;;) {
    if (!EVP_DigestInit_ex(&c, md, NULL)) {
      goto err;
    }
    if (addmd++) {
      if (!EVP_DigestUpdate(&c, md_buf, mds)) {
        goto err;
      }
    }
    if (!EVP_DigestUpdate(&c, data, data_len)) {
      goto err;
    }
    if (salt != NULL) {
      if (!EVP_DigestUpdate(&c, salt, PKCS5_SALT_LEN)) {
        goto err;
      }
    }
    if (!EVP_DigestFinal_ex(&c, md_buf, &mds)) {
      goto err;
    }

    for (i = 1; i < count; i++) {
      if (!EVP_DigestInit_ex(&c, md, NULL) ||
          !EVP_DigestUpdate(&c, md_buf, mds) ||
          !EVP_DigestFinal_ex(&c, md_buf, &mds)) {
        goto err;
      }
    }

    i = 0;
    if (nkey) {
      for (;;) {
        if (nkey == 0 || i == mds) {
          break;
        }
        if (key != NULL) {
          *(key++) = md_buf[i];
        }
        nkey--;
        i++;
      }
    }

    if (niv && i != mds) {
      for (;;) {
        if (niv == 0 || i == mds) {
          break;
        }
        if (iv != NULL) {
          *(iv++) = md_buf[i];
        }
        niv--;
        i++;
      }
    }
    if (nkey == 0 && niv == 0) {
      break;
    }
  }
  rv = EVP_CIPHER_key_length(type);

err:
  EVP_MD_CTX_cleanup(&c);
  OPENSSL_cleanse(md_buf, EVP_MAX_MD_SIZE);
  return rv;
}
