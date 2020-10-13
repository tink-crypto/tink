/**
 * Copyright 2018 Google Inc.
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

#import "TINKKeyTemplate.h"

typedef NS_ENUM(NSInteger, TINKHybridKeyTemplates) {
  /**
   * EciesAeadHkdfPrivateKey with the following parameters:
   *   KEM: ECDH over NIST P-256,
   *   DEM: AES128-GCM,
   *   KDF: HKDF-HMAC-SHA256 with an empty salt,
   *   OutputPrefixType: TINK
   */
  TINKEciesP256HkdfHmacSha256Aes128Gcm = 1,

  /**
   * EciesAeadHkdfPrivateKey with the following parameters:
   *   KEM: ECDH over NIST P-256
   *   DEM: AES128-CTR-HMAC-SHA256 with the following parameters:
   *        - AES key size: 16 bytes
   *        - AES CTR IV size: 16 bytes
   *        - HMAC key size: 32 bytes
   *        - HMAC tag size: 16 bytes
   *   KDF: HKDF-HMAC-SHA256 with an empty salt
   *   OutputPrefixType: TINK
   */
  TINKEciesP256HkdfHmacSha256Aes128CtrHmacSha256 = 2,
};

NS_ASSUME_NONNULL_BEGIN

/**
 * Pre-generated key templates for TINKHybrid key types.
 * One can use these templates to generate new TINKKeysetHandle object with fresh keys.
 *
 * Example:
 *
 * NSError *error = nil;
 * TINKHybridConfig *hybridConfig = [[TINKHybridConfig alloc] initWithError:&error];
 * if (!hybridConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:hybridConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKHybridKeyTemplate *template =
 *    [TINHybridKeyTemplate initWithKeyTemplate:TINKHybridEciesP256HkdfHmacSha256Aes128Gcm
 *                                        error:&error];
 * if (!template || error) {
 *   // handle error.
 * }
 *
 * TINKKeysetHandle *handle = [[TINKKeysetHandle alloc] initWithKeyTemplate:template
 *                                                                    error:&error];
 * if (!handle || error) {
 *   // handle error.
 * }
 *
 */
@interface TINKHybridKeyTemplate : TINKKeyTemplate

- (instancetype)init
    __attribute__((unavailable("Use -initWithKeyTemplate:error: instead.")));

/**
 * Creates a TINKHybridKeyTemplate that can be used to generate hybrid keysets.
 *
 * @param keyTemplate The hybrid key template to use.
 * @param error       If non-nil it will be populated with a descriptive error when the operation
 *                    fails.
 * @return            A TINKHybridKeyTemplate or nil in case of error.
 */
- (nullable instancetype)initWithKeyTemplate:(TINKHybridKeyTemplates)keyTemplate
                                       error:(NSError **)error NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
