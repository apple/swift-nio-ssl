/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2005 Nokia. All rights reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <CNIOBoringSSL_ssl.h>

#include <assert.h>
#include <string.h>

#include <CNIOBoringSSL_digest.h>
#include <CNIOBoringSSL_err.h>
#include <CNIOBoringSSL_md5.h>
#include <CNIOBoringSSL_mem.h>
#include <CNIOBoringSSL_nid.h>

#include "../crypto/internal.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

SSL3_STATE::SSL3_STATE()
    : skip_early_data(false),
      v2_hello_done(false),
      is_v2_hello(false),
      has_message(false),
      initial_handshake_complete(false),
      session_reused(false),
      send_connection_binding(false),
      channel_id_valid(false),
      key_update_pending(false),
      early_data_accepted(false),
      alert_dispatch(false),
      renegotiate_pending(false),
      used_hello_retry_request(false),
      was_key_usage_invalid(false) {}

SSL3_STATE::~SSL3_STATE() {}

bool tls_new(SSL *ssl) {
  UniquePtr<SSL3_STATE> s3 = MakeUnique<SSL3_STATE>();
  if (!s3) {
    return false;
  }

  // TODO(crbug.com/368805255): Fields that aren't used in DTLS should not be
  // allocated at all.
  // TODO(crbug.com/371998381): Don't create these in QUIC either, once the
  // placeholder QUIC ones for subsequent epochs are removed.
  if (!SSL_is_dtls(ssl)) {
    s3->aead_read_ctx = SSLAEADContext::CreateNullCipher();
    s3->aead_write_ctx = SSLAEADContext::CreateNullCipher();
    if (!s3->aead_read_ctx || !s3->aead_write_ctx) {
      return false;
    }
  }

  s3->hs = ssl_handshake_new(ssl);
  if (!s3->hs) {
    return false;
  }

  ssl->s3 = s3.release();
  return true;
}

void tls_free(SSL *ssl) {
  if (ssl->s3 == NULL) {
    return;
  }

  Delete(ssl->s3);
  ssl->s3 = NULL;
}

BSSL_NAMESPACE_END
