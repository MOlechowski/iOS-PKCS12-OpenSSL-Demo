#ifndef OPENSSL_HELPER_H
#define OPENSSL_HELPER_H

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

int generate_pkcs12_legacy(const char* pass_phrase,
                           const char* friendly_name,
                           EVP_PKEY* private_key,
                           X509* cert,
                           STACK_OF(X509)* ca_certs,
                           unsigned char** out_pkcs12,
                           int* out_pkcs12_len);

#endif /* OpenSSLGeneratePkcs12Legacy */
