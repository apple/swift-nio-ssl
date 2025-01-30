/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <CNIOBoringSSL_asn1.h>
#include <CNIOBoringSSL_evp.h>
#include <CNIOBoringSSL_obj.h>
#include <CNIOBoringSSL_stack.h>
#include <CNIOBoringSSL_x509.h>

#include "internal.h"

int X509_CRL_get_ext_count(const X509_CRL *x) {
  return (X509v3_get_ext_count(x->crl->extensions));
}

int X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos) {
  return (X509v3_get_ext_by_NID(x->crl->extensions, nid, lastpos));
}

int X509_CRL_get_ext_by_OBJ(const X509_CRL *x, const ASN1_OBJECT *obj,
                            int lastpos) {
  return (X509v3_get_ext_by_OBJ(x->crl->extensions, obj, lastpos));
}

int X509_CRL_get_ext_by_critical(const X509_CRL *x, int crit, int lastpos) {
  return (X509v3_get_ext_by_critical(x->crl->extensions, crit, lastpos));
}

X509_EXTENSION *X509_CRL_get_ext(const X509_CRL *x, int loc) {
  return (X509v3_get_ext(x->crl->extensions, loc));
}

X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc) {
  return (X509v3_delete_ext(x->crl->extensions, loc));
}

void *X509_CRL_get_ext_d2i(const X509_CRL *crl, int nid, int *out_critical,
                           int *out_idx) {
  return X509V3_get_d2i(crl->crl->extensions, nid, out_critical, out_idx);
}

int X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit,
                          unsigned long flags) {
  return X509V3_add1_i2d(&x->crl->extensions, nid, value, crit, flags);
}

int X509_CRL_add_ext(X509_CRL *x, const X509_EXTENSION *ex, int loc) {
  return (X509v3_add_ext(&(x->crl->extensions), ex, loc) != NULL);
}

int X509_get_ext_count(const X509 *x) {
  return (X509v3_get_ext_count(x->cert_info->extensions));
}

int X509_get_ext_by_NID(const X509 *x, int nid, int lastpos) {
  return (X509v3_get_ext_by_NID(x->cert_info->extensions, nid, lastpos));
}

int X509_get_ext_by_OBJ(const X509 *x, const ASN1_OBJECT *obj, int lastpos) {
  return (X509v3_get_ext_by_OBJ(x->cert_info->extensions, obj, lastpos));
}

int X509_get_ext_by_critical(const X509 *x, int crit, int lastpos) {
  return (X509v3_get_ext_by_critical(x->cert_info->extensions, crit, lastpos));
}

X509_EXTENSION *X509_get_ext(const X509 *x, int loc) {
  return (X509v3_get_ext(x->cert_info->extensions, loc));
}

X509_EXTENSION *X509_delete_ext(X509 *x, int loc) {
  return (X509v3_delete_ext(x->cert_info->extensions, loc));
}

int X509_add_ext(X509 *x, const X509_EXTENSION *ex, int loc) {
  return (X509v3_add_ext(&(x->cert_info->extensions), ex, loc) != NULL);
}

void *X509_get_ext_d2i(const X509 *x509, int nid, int *out_critical,
                       int *out_idx) {
  return X509V3_get_d2i(x509->cert_info->extensions, nid, out_critical,
                        out_idx);
}

int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
                      unsigned long flags) {
  return X509V3_add1_i2d(&x->cert_info->extensions, nid, value, crit, flags);
}

int X509_REVOKED_get_ext_count(const X509_REVOKED *x) {
  return (X509v3_get_ext_count(x->extensions));
}

int X509_REVOKED_get_ext_by_NID(const X509_REVOKED *x, int nid, int lastpos) {
  return (X509v3_get_ext_by_NID(x->extensions, nid, lastpos));
}

int X509_REVOKED_get_ext_by_OBJ(const X509_REVOKED *x, const ASN1_OBJECT *obj,
                                int lastpos) {
  return (X509v3_get_ext_by_OBJ(x->extensions, obj, lastpos));
}

int X509_REVOKED_get_ext_by_critical(const X509_REVOKED *x, int crit,
                                     int lastpos) {
  return (X509v3_get_ext_by_critical(x->extensions, crit, lastpos));
}

X509_EXTENSION *X509_REVOKED_get_ext(const X509_REVOKED *x, int loc) {
  return (X509v3_get_ext(x->extensions, loc));
}

X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc) {
  return (X509v3_delete_ext(x->extensions, loc));
}

int X509_REVOKED_add_ext(X509_REVOKED *x, const X509_EXTENSION *ex, int loc) {
  return (X509v3_add_ext(&(x->extensions), ex, loc) != NULL);
}

void *X509_REVOKED_get_ext_d2i(const X509_REVOKED *revoked, int nid,
                               int *out_critical, int *out_idx) {
  return X509V3_get_d2i(revoked->extensions, nid, out_critical, out_idx);
}

int X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit,
                              unsigned long flags) {
  return X509V3_add1_i2d(&x->extensions, nid, value, crit, flags);
}
