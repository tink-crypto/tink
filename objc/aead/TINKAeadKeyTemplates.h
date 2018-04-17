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

@class TINKPBKeyTemplate;

NS_ASSUME_NONNULL_BEGIN

/**
 * Pre-generated TINKPBKeyTemplate for TINKAead key types. One can use these templates
 * to generate new TINKKeysetHandle object with fresh keys.
 *
 * Example:
 *
 * NSError *error = nil;
 * TINKAeadConfig *aeadConfig = [[TINKAeadConfig alloc] initWithVersion:TINKVersion1_1_0
 *                                                                error:&error];
 * if (!aeadConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:aeadConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKKeysetHandle *handle = [[TINKKeysetHandle alloc]
 *     initWithKeyTemplate:[TINKAeadKeyTemplates keyTemplateForAes128Gcm]
 *                   error:&error];
 * if (!handle || error) {
 *   // handle error.
 * }
 *
 */
@interface TINKAeadKeyTemplates : NSObject

- (nullable instancetype)init NS_UNAVAILABLE;

/**
 * Returns a TINKPBKeyTemplate that generates new instances of TINKAesGcmKey
 * with the following parameters:
 * - key size: 16 bytes
 * - IV size: 12 bytes
 * - tag size: 16 bytes
 * OutputPrefixType: TINK
 */
+ (TINKPBKeyTemplate *)keyTemplateForAes128Gcm;

/**
 * Returns a TINKPBKeyTemplate that generates new instances of TINKAesGcmKey
 * with the following parameters:
 * - key size: 32 bytes
 * - IV size: 12 bytes
 * - tag size: 16 bytes
 * OutputPrefixType: TINK
 */
+ (TINKPBKeyTemplate *)keyTemplateForAes256Gcm;

/**
 * Returns a KeyTemplate that generates new instances of AesCtrHmacAeadKey
 * with the following parameters:
 * - AES key size: 16 bytes
 * - AES IV size: 16 bytes
 * - HMAC key size: 32 bytes
 * - HMAC tag size: 16 bytes
 * - HMAC hash function: SHA256
 * - OutputPrefixType: TINK
 */
+ (TINKPBKeyTemplate *)keyTemplateForAes128CtrHmacSha256;

/**
 * Returns a KeyTemplate that generates new instances of AesCtrHmacAeadKey
 * with the following parameters:
 * - AES key size: 32 bytes
 * - AES IV size: 16 bytes
 * - HMAC key size: 32 bytes
 * - HMAC tag size: 32 bytes
 * - HMAC hash function: SHA256
 * - OutputPrefixType: TINK
 */
+ (TINKPBKeyTemplate *)keyTemplateForAes256CtrHmacSha256;

@end

NS_ASSUME_NONNULL_END
