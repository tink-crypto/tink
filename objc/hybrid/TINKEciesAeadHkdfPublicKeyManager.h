/**
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **************************************************************************
 */

#import <Foundation/Foundation.h>

#import "objc/TINKKeyManager.h"
#import "objc/hybrid/TINKHybridEncryptKeyManager.h"

@class TINKPBKeyData;
@class TINKPBEciesAeadHkdfPublicKey;
@class TINKPBKeyTemplate;
@protocol TINKHybridEncrypt;

NS_ASSUME_NONNULL_BEGIN

@interface TINKEciesAeadHkdfPublicKeyManager : TINKHybridEncryptKeyManager <TINKKeyManager>

/** The version of this key manager. */
@property(nonatomic, readonly) NSUInteger version;

/** The key type handled by this manager. */
@property(nonatomic, readonly) NSString *keyType;

/**
 * Constructs a ECIES-AEAD-HKDF primitive for the given @c keyData that conforms to the
 * HybridEncrypt protocol.
 *
 * @param keyData A TINKPBKeyData protocol buffer that must contain EciesAeadHkdfPublicKey.
 * @return An instance that conforms to the HybridEncrypt protocol. In case of error, it returns nil
 *         and sets the supplied @c error (if non-nil) with a descriptive error message.
 */
- (nullable id<TINKHybridEncrypt>)primitiveFromKeyData:(TINKPBKeyData *)keyData
                                                 error:(NSError **)error;

/**
 * Constructs a ECIES-AEAD-HKDF primitive for the given @c key that conforms to the
 * HybridEncrypt protocol.
 *
 * @param key A TINKPBEciesAeadHkdfPublicKey protocol buffer.
 * @return An instance that conforms to the HybridEncrypt protocol. In case of error, it returns nil
 *         and sets the supplied @c error (if non-nil) with a descriptive error message.
 */
- (nullable id<TINKHybridEncrypt>)primitiveFromKey:(TINKPBEciesAeadHkdfPublicKey *)key
                                             error:(NSError **)error;

/**
 * Generates a new random TINKPBEciesAeadHkdfPublicKey, based on the specified @c keyTemplate which
 * must contain EciesAeadHkdfKeyFormat proto.
 */
- (nullable TINKPBEciesAeadHkdfPublicKey *)newKeyFromTemplate:(TINKPBKeyTemplate *)keyTemplate
                                                        error:(NSError **)error;

/** True if the key manager supports the supplied @c keyType. */
- (BOOL)shouldSupportKeyType:(NSString *)keyType;

@end

NS_ASSUME_NONNULL_END
