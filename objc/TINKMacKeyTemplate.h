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

typedef NS_ENUM(NSInteger, TINKMacKeyTemplates) {
  /**
   * HmacKey with the following parameters:
   *   - key size: 32 bytes
   *   - tag size: 16 bytes
   *   - hash function: SHA256
   *   - OutputPrefixType: TINK
   */
  TINKHmacSha256HalfSizeTag = 1,

  /**
   * HmacKey with the following parameters:
   *   - key size: 32 bytes
   *   - tag size: 32 bytes
   *   - hash function: SHA256
   *   - OutputPrefixType: TINK
   */
  TINKHmacSha256 = 2,

  /**
   * HmacKey with the following parameters:
   *   - key size: 64 bytes
   *   - tag size: 32 bytes
   *   - hash function: SHA512
   *   - OutputPrefixType: TINK
   */
  TINKHmacSha512HalfSizeTag = 3,

  /**
   * HmacKey with the following parameters:
   *   - key size: 64 bytes
   *   - tag size: 64 bytes
   *   - hash function: SHA512
   *   - OutputPrefixType: TINK
   */
  TINKHmacSha512 = 4,

  /**
   * AesCmacKey with the following parameters:
   *   - key size: 32 bytes
   *   - tag size: 16 bytes
   *   - OutputPrefixType: TINK
   */
  TINKAesCmac = 5,
};

NS_ASSUME_NONNULL_BEGIN

/**
 * Pre-generated key templates for TINKMac key types.
 * One can use these templates to generate new TINKKeysetHandle object with fresh keys.
 *
 * Example:
 *
 * NSError *error = nil;
 * TINKMacConfig *macConfig = [[TINMacConfig alloc] initWithError:&error];
 * if (!macConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:macConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKMacKeyTemplate *template =
 *    [TINMacKeyTemplate initWithKeyTemplate:TINKHmacSha256
 *                                     error:&error];
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
@interface TINKMacKeyTemplate : TINKKeyTemplate

- (instancetype)init
    __attribute__((unavailable("Use -initWithKeyTemplate:error: instead.")));

/**
 * Creates a TINKMacKeyTemplate that can be used to generate mac keysets.
 *
 * @param keyTemplate The mac key template to use.
 * @param error       If non-nil it will be populated with a descriptive error when the operation
 *                    fails.
 * @return            A TINKMacKeyTemplate or nil in case of error.
 */
- (nullable instancetype)initWithKeyTemplate:(TINKMacKeyTemplates)keyTemplate
                                       error:(NSError **)error NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
