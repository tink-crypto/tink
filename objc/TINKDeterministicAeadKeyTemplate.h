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

typedef NS_ENUM(NSInteger, TINKDeterministicAeadKeyTemplates) {
  /**
   * Aes256SivKey with the following parameters:
   *   Key size: 64 bytes
   *   OutputPrefixType: TINK
   */
  TINKAes256Siv = 1,
};

NS_ASSUME_NONNULL_BEGIN

/**
 * Pre-generated key templates for TINKDeterministicAead key types.
 * One can use these templates to generate new TINKKeysetHandle object with fresh keys.
 *
 * Example:
 *
 * NSError *error = nil;
 * TINKDeterministicAeadConfig *aeadConfig =
 *    [[TINKDeterministicAeadConfig alloc] initWithError:&error];
 * if (!aeadConfig || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:aeadConfig error:&error]) {
 *   // handle error.
 * }
 *
 * TINKDeterministicAeadKeyTemplate *tpl =
 *    [[TINAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256Siv
 *                                              error:&error];
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
@interface TINKDeterministicAeadKeyTemplate : TINKKeyTemplate

- (nullable instancetype)init
    __attribute__((unavailable("Use -initWithKeyTemplate:error: instead.")));

/**
 * Creates a TINKDeterministicAeadKeyTemplate that can be used to generate aead keysets.
 *
 * @param keyTemplate The deterministic aead key template to use.
 * @param error       If non-nil it will be populated with a descriptive error when the operation
 *                    fails.
 * @return            A TINKDeterministicAeadKeyTemplate or nil in case of error.
 */
- (nullable instancetype)initWithKeyTemplate:(TINKDeterministicAeadKeyTemplates)keyTemplate
                                       error:(NSError **)error NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
