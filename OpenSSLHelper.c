#include "OpenSSLHelper.h"
#include <string.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

#define ERROR_BUFFER_SIZE 1024

OSSL_PROVIDER *legacy_provider = NULL;
OSSL_PROVIDER *default_provider = NULL;

void print_openssl_errors(void) {
    char error_buffer[ERROR_BUFFER_SIZE];
    unsigned long err;
    int index = 0;

    error_buffer[0] = '\0';  // Ensure the buffer is initially empty

    while ((err = ERR_get_error()) != 0) {
        if (index > 0) {
            strncat(error_buffer, "\n", ERROR_BUFFER_SIZE - strlen(error_buffer) - 1);
        }
        ERR_error_string_n(err, error_buffer + strlen(error_buffer),
                           ERROR_BUFFER_SIZE - strlen(error_buffer));
        index++;
    }

    if (index > 0) {
        fprintf(stderr, "OpenSSL Errors:\n%s\n", error_buffer);
    }
}

void initialize_openssl(void) {
    legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (legacy_provider == NULL) {
        fprintf(stderr, "Failed to load legacy provider\n");
    }

    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (default_provider == NULL) {
        fprintf(stderr, "Failed to load default provider\n");
        OSSL_PROVIDER_unload(legacy_provider);
    }
}

void cleanup_openssl(void) {
    if (legacy_provider != NULL) {
        OSSL_PROVIDER_unload(legacy_provider);
    }
    if (default_provider != NULL) {
        OSSL_PROVIDER_unload(default_provider);
    }
}

int generate_pkcs12(const char* pass_phrase, const char* friendly_name, EVP_PKEY* private_key,
                    X509* cert, STACK_OF(X509)* ca_certs, unsigned char** out_pkcs12, int* out_pkcs12_len) {
    PKCS12 *p12 = NULL;
    BIO *bio = NULL;
    int result = 0;

    initialize_openssl();

    if (legacy_provider == NULL || default_provider == NULL) {
        print_openssl_errors();
        return 0;
    }

    p12 = PKCS12_create_ex(pass_phrase, friendly_name, private_key, cert, ca_certs,
                           NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                           NID_pbe_WithSHA1And40BitRC2_CBC,
                           PKCS12_DEFAULT_ITER, -1, 0, NULL, NULL);

    if (p12 == NULL) {
        print_openssl_errors();
        return 0;
    }

    if (!PKCS12_set_mac(p12, pass_phrase, -1, NULL, 0, 1, EVP_sha1())) {
        print_openssl_errors();
        PKCS12_free(p12);
        return 0;
    }

    bio = BIO_new(BIO_s_mem());
    if (!i2d_PKCS12_bio(bio, p12)) {
        print_openssl_errors();
        BIO_free(bio);
        PKCS12_free(p12);
        return 0;
    }

    *out_pkcs12_len = BIO_pending(bio);
    *out_pkcs12 = (unsigned char*)OPENSSL_malloc(*out_pkcs12_len);
    if (*out_pkcs12 == NULL) {
        print_openssl_errors();
        BIO_free(bio);
        PKCS12_free(p12);
        return 0;
    }

    BIO_read(bio, *out_pkcs12, *out_pkcs12_len);

    result = 1;

    BIO_free(bio);
    PKCS12_free(p12);
    cleanup_openssl();

    return result;
}
