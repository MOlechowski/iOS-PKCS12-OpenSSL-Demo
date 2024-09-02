#import <Foundation/Foundation.h>

#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include "OpenSSLCryptoOperationsWrapper.h"
#include "OpenSSLGeneratePkcs12Legacy.h"

@implementation OpenSSLCryptoOperationsWrapper

- (nullable NSData *)createPKCS12FromPKCS12Data:(nonnull NSData *)pkcs12Data
                             originalPassphrase:(nonnull NSString *)originalPassphrase
                                  newPassphrase:(nonnull NSString *)newPassphrase
                                           name:(nonnull NSString *)name {
    const char* passOriginal = [originalPassphrase UTF8String];
    const char* passNew = [newPassphrase UTF8String];
    const char* friendlyName = [name UTF8String];;

    // Parse the original PKCS12
    BIO* bio = BIO_new_mem_buf([pkcs12Data bytes], (int)[pkcs12Data length]);
    PKCS12* p12 = d2i_PKCS12_bio(bio, NULL);
    BIO_free(bio);

    if (!p12) {
        NSLog(@"Failed to read PKCS12 data");
        return nil;
    }

    // Extract the private key, certificate, and CA certs
    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    STACK_OF(X509)* ca = NULL;

    // Verify original p12
    if (!PKCS12_parse(p12, passOriginal, &pkey, &cert, &ca)) {
        NSLog(@"Failed to parse PKCS12");
        PKCS12_free(p12);
        return nil;
    }

    PKCS12_free(p12);

    // Generate new PKCS12
    unsigned char* outPKCS12 = NULL;
    int outPKCS12Len = 0;

    int result = generate_pkcs12_legacy(passNew, friendlyName, pkey, cert, ca, &outPKCS12, &outPKCS12Len);

    // Clean up
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);

    if (result != 1) {
        NSLog(@"Failed to generate new PKCS12");
        return nil;
    }

    NSData* newPKCS12Data = [NSData dataWithBytes:outPKCS12 length:outPKCS12Len];
    OPENSSL_free(outPKCS12);

    return newPKCS12Data;
}

@end
