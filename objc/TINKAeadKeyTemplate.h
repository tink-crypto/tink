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

typedef NS_ENUM(NSInteger, TINKAeadKeyTemplates) {
  /**
   * AesGcmKey with the following parameters:
   *   Key size: 16 bytes
   *   IV size: 12 bytes
   *   Tag size: 16 bytes
   *   OutputPrefixType: TINK
   */
  TINKAes128Gcm = 1,

  /**
   * AesGcmKey with the following parameters:
   *   Key size: 32 bytes
   *   IV size: 12 bytes
   *   Tag size: 16 bytes
   *   OutputPrefixType: TINK
   */
  TINKAes256Gcm = 2,

  /**
   * AesCtrHmacAeadKey with the following parameters:
   *   AES key size: 16 bytes
   *   AES IV size: 16 bytes
   *   HMAC key size: 32 bytes
   *   HMAC tag size: 16 bytes
   *   HMAC hash function: SHA256
   *   OutputPrefixType: TINK
   */
  TINKAes128CtrHmacSha256 = 3,

  /**
   * AesCtrHmacAeadKey with the following parameters:
   *   AES key size: 32 bytes
   *   AES IV size: 16 bytes
   *   HMAC key size: 32 bytes
   *   HMAC tag size: 32 bytes
   *   HMAC hash function: SHA256
   *   OutputPrefixType: TINK
   */
  TINKAes256CtrHmacSha256 = 4,

  /**
   * AesEaxKey with the following parameters:
   *   Key size: 16 bytes
   *   IV size: 16 bytes
   *   Tag size: 16 bytes
   *   OutputPrefixType: TINK
   */
  TINKAes128Eax = 5,

  /**
   * AesEaxKey with the following parameters:
   *   Key size: 32 bytes
   *   IV size: 16 bytes
   *   Tag size: 16 bytes
   *   OutputPrefixType: TINK
   */
  TINKAes256Eax = 6,

  /**
   * XChaCha20Poly1305Key with the following parameters:
   *    XChacha20 key size: 32 bytes
   *    IV size: 24 bytes
   *    OutputPrefixType: TINK
   */
  TINKXChaCha20Poly1305 = 7,

  /**
   * AesGcmKey with the following parameters:
   *   Key size: 32 bytes
   *   IV size: 12 bytes
   *   Tag size: 16 bytes
   *   OutputPrefixType: RAW
   */
  TINKAes256GcmNoPrefix = 8,

  /**
   * AesGcmKey with the following parameters:
   *   Key size: 16 bytes
   *   IV size: 12 bytes
   *   Tag size: 16 bytes
   *   OutputPrefixType: RAW
   */
  TINKAes128GcmNoPrefix = 9,
};

NS_ASSUME_NONNULL_BEGIN

/**
 * Pre-generated key templates for TINKAead key types.
 * One can use these templates to generate new TINKKeysetHandle object with fresh keys.
 *
 * Example:
 *
 * NSError *error = nil;
 * TINKAeadConfig *aeadConfig = [[TINKAeadConfig alloc] initWithError:&error];
 * if (!aeadConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:aeadConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKAeadKeyTemplate *tpl = [[TINAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128Gcm
 *                                                                      error:&error];
 * if (!tpl || error) {
 *   // handle error.
 * }
 *
 * TINKKeysetHandle *handle = [[TINKKeysetHandle alloc] initWithKeyTemplate:tpl error:&error];
 * if (!handle || error) {
 *   // handle error.
 * }
 *
 */
@interface TINKAeadKeyTemplate : TINKKeyTemplate

- (instancetype)init __attribute__((unavailable("Use -initWithKeyTemplate:error: instead.")));

/**
 * Creates a TINKAeadKeyTemplate that can be used to generate aead keysets.
 *
 * @param keyTemplate The aead key template to use.
 * @param error       If non-nil it will be populated with a descriptive error when the operation
 *                    fails.
 * @return            A TINKAeadKeyTemplate or nil in case of error.
 */
- (nullable instancetype)initWithKeyTemplate:(TINKAeadKeyTemplates)keyTemplate
                                       error:(NSError **)error NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
