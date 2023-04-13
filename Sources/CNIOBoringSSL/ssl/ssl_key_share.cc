/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <CNIOBoringSSL_ssl.h>

#include <assert.h>
#include <string.h>

#include <utility>

#include <CNIOBoringSSL_bn.h>
#include <CNIOBoringSSL_bytestring.h>
#include <CNIOBoringSSL_curve25519.h>
#include <CNIOBoringSSL_ec.h>
#include <CNIOBoringSSL_err.h>
#include <CNIOBoringSSL_kyber.h>
#include <CNIOBoringSSL_hrss.h>
#include <CNIOBoringSSL_mem.h>
#include <CNIOBoringSSL_nid.h>
#include <CNIOBoringSSL_rand.h>

#include "internal.h"
#include "../crypto/internal.h"

BSSL_NAMESPACE_BEGIN

namespace {

class ECKeyShare : public SSLKeyShare {
 public:
  ECKeyShare(int nid, uint16_t group_id)
      : group_(EC_GROUP_new_by_curve_name(nid)), group_id_(group_id) {}

  uint16_t GroupID() const override { return group_id_; }

  bool Generate(CBB *out) override {
    assert(!private_key_);
    // Generate a private key.
    private_key_.reset(BN_new());
    if (!group_ || !private_key_ ||
        !BN_rand_range_ex(private_key_.get(), 1,
                          EC_GROUP_get0_order(group_))) {
      return false;
    }

    // Compute the corresponding public key and serialize it.
    UniquePtr<EC_POINT> public_key(EC_POINT_new(group_));
    if (!public_key ||
        !EC_POINT_mul(group_, public_key.get(), private_key_.get(),
                      nullptr, nullptr, /*ctx=*/nullptr) ||
        !EC_POINT_point2cbb(out, group_, public_key.get(),
                            POINT_CONVERSION_UNCOMPRESSED, /*ctx=*/nullptr)) {
      return false;
    }

    return true;
  }

  bool Encap(CBB *out_ciphertext, Array<uint8_t> *out_secret,
             uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    // ECDH may be fit into a KEM-like abstraction by using a second keypair's
    // public key as the ciphertext.
    *out_alert = SSL_AD_INTERNAL_ERROR;
    return Generate(out_ciphertext) && Decap(out_secret, out_alert, peer_key);
  }

  bool Decap(Array<uint8_t> *out_secret, uint8_t *out_alert,
             Span<const uint8_t> ciphertext) override {
    assert(group_);
    assert(private_key_);
    *out_alert = SSL_AD_INTERNAL_ERROR;

    UniquePtr<EC_POINT> peer_point(EC_POINT_new(group_));
    UniquePtr<EC_POINT> result(EC_POINT_new(group_));
    UniquePtr<BIGNUM> x(BN_new());
    if (!peer_point || !result || !x) {
      return false;
    }

    if (ciphertext.empty() || ciphertext[0] != POINT_CONVERSION_UNCOMPRESSED ||
        !EC_POINT_oct2point(group_, peer_point.get(), ciphertext.data(),
                            ciphertext.size(), /*ctx=*/nullptr)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      *out_alert = SSL_AD_DECODE_ERROR;
      return false;
    }

    // Compute the x-coordinate of |peer_key| * |private_key_|.
    if (!EC_POINT_mul(group_, result.get(), NULL, peer_point.get(),
                      private_key_.get(), /*ctx=*/nullptr) ||
        !EC_POINT_get_affine_coordinates_GFp(group_, result.get(), x.get(),
                                             NULL,
                                             /*ctx=*/nullptr)) {
      return false;
    }

    // Encode the x-coordinate left-padded with zeros.
    Array<uint8_t> secret;
    if (!secret.Init((EC_GROUP_get_degree(group_) + 7) / 8) ||
        !BN_bn2bin_padded(secret.data(), secret.size(), x.get())) {
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

  bool SerializePrivateKey(CBB *out) override {
    assert(group_);
    assert(private_key_);
    // Padding is added to avoid leaking the length.
    size_t len = BN_num_bytes(EC_GROUP_get0_order(group_));
    return BN_bn2cbb_padded(out, len, private_key_.get());
  }

  bool DeserializePrivateKey(CBS *in) override {
    assert(!private_key_);
    private_key_.reset(BN_bin2bn(CBS_data(in), CBS_len(in), nullptr));
    return private_key_ != nullptr;
  }

 private:
  UniquePtr<BIGNUM> private_key_;
  const EC_GROUP *const group_ = nullptr;
  uint16_t group_id_;
};

class X25519KeyShare : public SSLKeyShare {
 public:
  X25519KeyShare() {}

  uint16_t GroupID() const override { return SSL_CURVE_X25519; }

  bool Generate(CBB *out) override {
    uint8_t public_key[32];
    X25519_keypair(public_key, private_key_);
    return !!CBB_add_bytes(out, public_key, sizeof(public_key));
  }

  bool Encap(CBB *out_ciphertext, Array<uint8_t> *out_secret,
             uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    // X25519 may be fit into a KEM-like abstraction by using a second keypair's
    // public key as the ciphertext.
    *out_alert = SSL_AD_INTERNAL_ERROR;
    return Generate(out_ciphertext) && Decap(out_secret, out_alert, peer_key);
  }

  bool Decap(Array<uint8_t> *out_secret, uint8_t *out_alert,
             Span<const uint8_t> ciphertext) override {
    *out_alert = SSL_AD_INTERNAL_ERROR;

    Array<uint8_t> secret;
    if (!secret.Init(32)) {
      return false;
    }

    if (ciphertext.size() != 32 ||  //
        !X25519(secret.data(), private_key_, ciphertext.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

  bool SerializePrivateKey(CBB *out) override {
    return CBB_add_bytes(out, private_key_, sizeof(private_key_));
  }

  bool DeserializePrivateKey(CBS *in) override {
    if (CBS_len(in) != sizeof(private_key_) ||
        !CBS_copy_bytes(in, private_key_, sizeof(private_key_))) {
      return false;
    }
    return true;
  }

 private:
  uint8_t private_key_[32];
};

class CECPQ2KeyShare : public SSLKeyShare {
 public:
  CECPQ2KeyShare() {}

  uint16_t GroupID() const override { return SSL_CURVE_CECPQ2; }

  bool Generate(CBB *out) override {
    uint8_t x25519_public_key[32];
    X25519_keypair(x25519_public_key, x25519_private_key_);

    uint8_t hrss_entropy[HRSS_GENERATE_KEY_BYTES];
    HRSS_public_key hrss_public_key;
    RAND_bytes(hrss_entropy, sizeof(hrss_entropy));
    if (!HRSS_generate_key(&hrss_public_key, &hrss_private_key_,
                           hrss_entropy)) {
      return false;
    }

    uint8_t hrss_public_key_bytes[HRSS_PUBLIC_KEY_BYTES];
    HRSS_marshal_public_key(hrss_public_key_bytes, &hrss_public_key);

    if (!CBB_add_bytes(out, x25519_public_key, sizeof(x25519_public_key)) ||
        !CBB_add_bytes(out, hrss_public_key_bytes,
                       sizeof(hrss_public_key_bytes))) {
      return false;
    }

    return true;
  }

  bool Encap(CBB *out_ciphertext, Array<uint8_t> *out_secret,
             uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    Array<uint8_t> secret;
    if (!secret.Init(32 + HRSS_KEY_BYTES)) {
      return false;
    }

    uint8_t x25519_public_key[32];
    X25519_keypair(x25519_public_key, x25519_private_key_);

    HRSS_public_key peer_public_key;
    if (peer_key.size() != 32 + HRSS_PUBLIC_KEY_BYTES ||
        !HRSS_parse_public_key(&peer_public_key, peer_key.data() + 32) ||
        !X25519(secret.data(), x25519_private_key_, peer_key.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    uint8_t ciphertext[HRSS_CIPHERTEXT_BYTES];
    uint8_t entropy[HRSS_ENCAP_BYTES];
    RAND_bytes(entropy, sizeof(entropy));

    if (!HRSS_encap(ciphertext, secret.data() + 32, &peer_public_key,
                    entropy) ||
        !CBB_add_bytes(out_ciphertext, x25519_public_key,
                       sizeof(x25519_public_key)) ||
        !CBB_add_bytes(out_ciphertext, ciphertext, sizeof(ciphertext))) {
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

  bool Decap(Array<uint8_t> *out_secret, uint8_t *out_alert,
             Span<const uint8_t> ciphertext) override {
    *out_alert = SSL_AD_INTERNAL_ERROR;

    Array<uint8_t> secret;
    if (!secret.Init(32 + HRSS_KEY_BYTES)) {
      return false;
    }

    if (ciphertext.size() != 32 + HRSS_CIPHERTEXT_BYTES ||
        !X25519(secret.data(), x25519_private_key_, ciphertext.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    if (!HRSS_decap(secret.data() + 32, &hrss_private_key_,
                    ciphertext.data() + 32, ciphertext.size() - 32)) {
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

 private:
  uint8_t x25519_private_key_[32];
  HRSS_private_key hrss_private_key_;
};

class X25519Kyber768KeyShare : public SSLKeyShare {
 public:
  X25519Kyber768KeyShare() {}

  uint16_t GroupID() const override { return SSL_CURVE_X25519KYBER768; }

  bool Generate(CBB *out) override {
    uint8_t x25519_public_key[32];
    X25519_keypair(x25519_public_key, x25519_private_key_);

    uint8_t kyber_public_key[KYBER_PUBLIC_KEY_BYTES];
    KYBER_generate_key(kyber_public_key, &kyber_private_key_);

    if (!CBB_add_bytes(out, x25519_public_key, sizeof(x25519_public_key)) ||
        !CBB_add_bytes(out, kyber_public_key, sizeof(kyber_public_key))) {
      return false;
    }

    return true;
  }

  bool Encap(CBB *out_ciphertext, Array<uint8_t> *out_secret,
             uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    Array<uint8_t> secret;
    if (!secret.Init(32 + 32)) {
      return false;
    }

    uint8_t x25519_public_key[32];
    X25519_keypair(x25519_public_key, x25519_private_key_);
    KYBER_public_key peer_kyber_pub;
    CBS peer_key_cbs;
    CBS peer_x25519_cbs;
    CBS peer_kyber_cbs;
    CBS_init(&peer_key_cbs, peer_key.data(), peer_key.size());
    if (!CBS_get_bytes(&peer_key_cbs, &peer_x25519_cbs, 32) ||
        !CBS_get_bytes(&peer_key_cbs, &peer_kyber_cbs,
                       KYBER_PUBLIC_KEY_BYTES) ||
        CBS_len(&peer_key_cbs) != 0 ||
        !X25519(secret.data(), x25519_private_key_,
                CBS_data(&peer_x25519_cbs)) ||
        !KYBER_parse_public_key(&peer_kyber_pub, &peer_kyber_cbs)) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    uint8_t kyber_ciphertext[KYBER_CIPHERTEXT_BYTES];
    KYBER_encap(kyber_ciphertext, secret.data() + 32, secret.size() - 32,
                &peer_kyber_pub);

    if (!CBB_add_bytes(out_ciphertext, x25519_public_key,
                       sizeof(x25519_public_key)) ||
        !CBB_add_bytes(out_ciphertext, kyber_ciphertext,
                       sizeof(kyber_ciphertext))) {
      return false;
    }

    *out_secret = std::move(secret);
    return true;
  }

  bool Decap(Array<uint8_t> *out_secret, uint8_t *out_alert,
             Span<const uint8_t> ciphertext) override {
    *out_alert = SSL_AD_INTERNAL_ERROR;

    Array<uint8_t> secret;
    if (!secret.Init(32 + 32)) {
      return false;
    }

    if (ciphertext.size() != 32 + KYBER_CIPHERTEXT_BYTES ||
        !X25519(secret.data(), x25519_private_key_, ciphertext.data())) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
      return false;
    }

    KYBER_decap(secret.data() + 32, secret.size() - 32, ciphertext.data() + 32,
                &kyber_private_key_);
    *out_secret = std::move(secret);
    return true;
  }

 private:
  uint8_t x25519_private_key_[32];
  KYBER_private_key kyber_private_key_;
};

class P256Kyber768KeyShare : public SSLKeyShare {
 public:
  P256Kyber768KeyShare() {}

  uint16_t GroupID() const override { return SSL_CURVE_P256KYBER768; }

  bool Generate(CBB *out) override {
    // There is no implementation on Kyber in BoringSSL. BoringSSL must be
    // patched for this KEM to be workable. It is not enabled by default.
    return false;
  }

  bool Encap(CBB *out_ciphertext, Array<uint8_t> *out_secret,
             uint8_t *out_alert, Span<const uint8_t> peer_key) override {
    return false;
  }

  bool Decap(Array<uint8_t> *out_secret, uint8_t *out_alert,
             Span<const uint8_t> ciphertext) override {
    return false;
  }
};

constexpr NamedGroup kNamedGroups[] = {
    {NID_secp224r1, SSL_CURVE_SECP224R1, "P-224", "secp224r1"},
    {NID_X9_62_prime256v1, SSL_CURVE_SECP256R1, "P-256", "prime256v1"},
    {NID_secp384r1, SSL_CURVE_SECP384R1, "P-384", "secp384r1"},
    {NID_secp521r1, SSL_CURVE_SECP521R1, "P-521", "secp521r1"},
    {NID_X25519, SSL_CURVE_X25519, "X25519", "x25519"},
    {NID_CECPQ2, SSL_CURVE_CECPQ2, "CECPQ2", "CECPQ2"},
    {NID_X25519Kyber768, SSL_CURVE_X25519KYBER768, "X25519KYBER",
     "X25519Kyber"},
    {NID_P256Kyber768, SSL_CURVE_P256KYBER768, "P256KYBER", "P256Kyber"},
};

}  // namespace

Span<const NamedGroup> NamedGroups() {
  return MakeConstSpan(kNamedGroups, OPENSSL_ARRAY_SIZE(kNamedGroups));
}

UniquePtr<SSLKeyShare> SSLKeyShare::Create(uint16_t group_id) {
  switch (group_id) {
    case SSL_CURVE_SECP224R1:
      return MakeUnique<ECKeyShare>(NID_secp224r1, SSL_CURVE_SECP224R1);
    case SSL_CURVE_SECP256R1:
      return MakeUnique<ECKeyShare>(NID_X9_62_prime256v1, SSL_CURVE_SECP256R1);
    case SSL_CURVE_SECP384R1:
      return MakeUnique<ECKeyShare>(NID_secp384r1, SSL_CURVE_SECP384R1);
    case SSL_CURVE_SECP521R1:
      return MakeUnique<ECKeyShare>(NID_secp521r1, SSL_CURVE_SECP521R1);
    case SSL_CURVE_X25519:
      return MakeUnique<X25519KeyShare>();
    case SSL_CURVE_CECPQ2:
      return MakeUnique<CECPQ2KeyShare>();
    case SSL_CURVE_X25519KYBER768:
      return MakeUnique<X25519Kyber768KeyShare>();
    case SSL_CURVE_P256KYBER768:
      return MakeUnique<P256Kyber768KeyShare>();
    default:
      return nullptr;
  }
}

bool ssl_nid_to_group_id(uint16_t *out_group_id, int nid) {
  for (const auto &group : kNamedGroups) {
    if (group.nid == nid) {
      *out_group_id = group.group_id;
      return true;
    }
  }
  return false;
}

bool ssl_name_to_group_id(uint16_t *out_group_id, const char *name, size_t len) {
  for (const auto &group : kNamedGroups) {
    if (len == strlen(group.name) &&
        !strncmp(group.name, name, len)) {
      *out_group_id = group.group_id;
      return true;
    }
    if (len == strlen(group.alias) &&
        !strncmp(group.alias, name, len)) {
      *out_group_id = group.group_id;
      return true;
    }
  }
  return false;
}

BSSL_NAMESPACE_END

using namespace bssl;

const char* SSL_get_curve_name(uint16_t group_id) {
  for (const auto &group : kNamedGroups) {
    if (group.group_id == group_id) {
      return group.name;
    }
  }
  return nullptr;
}
