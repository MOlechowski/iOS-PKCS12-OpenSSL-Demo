#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface OpenSSlWrapper : NSObject

- (nullable NSData *)createPKCS12FromPKCS12Data:(NSData *)pkcs12Data
                             originalPassphrase:(NSString *)originalPassphrase
                                  newPassphrase:(NSString *)newPassphrase
                                           name:(NSString *)name;

@end

NS_ASSUME_NONNULL_END
