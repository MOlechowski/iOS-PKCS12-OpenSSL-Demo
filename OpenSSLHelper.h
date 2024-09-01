#ifndef OPENSSL_HELPER_H
#define OPENSSL_HELPER_H

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

void initialize_openssl(void);

BIO* create_pkcs12_from_pkcs12(const unsigned char* data,
                               long data_length,
                               const char* original_passphrase,
                               const char* new_passphrase);

int generate_pkcs12(const char* pass_phrase,
                    const char* friendly_name,
                    EVP_PKEY* private_key,
                    X509* cert,
                    STACK_OF(X509)* ca_certs,
                    unsigned char** out_pkcs12,
                    int* out_pkcs12_len);

#endif /* OPENSSL_HELPER_H */
