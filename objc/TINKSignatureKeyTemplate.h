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

typedef NS_ENUM(NSInteger, TINKSignatureKeyTemplates) {
  /**
   * EcdsaPrivateKey with the following parameters:
   *   - EC curve: NIST P-256
   *   - hash function: SHA256
   *   - signature encoding: DER
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP256 = 1,

  /**
   * EcdsaPrivateKey with the following parameters:
   *   - EC curve: NIST P-384
   *   - hash function: SHA512
   *   - signature encoding: DER
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP384 = 2,

  /**
   * EcdsaPrivateKey with the following parameters:
   *   - EC curve: NIST P-521
   *   - hash function: SHA512
   *   - signature encoding: DER
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP521 = 3,
};

NS_ASSUME_NONNULL_BEGIN

/**
 * Pre-generated key templates for signature key types.
 * One can use these templates to generate new TINKKeysetHandle object with fresh keys.
 *
 * Example:
 *
 * NSError *error = nil;
 * TINKSignatureConfig *config = [[TINKSignatureConfig alloc] initWithError:&error];
 * if (!config || error) {
 *   // handle error.
 * }
 *
 * if (![TINKConfig registerConfig:config error:&error]) {
 *   // handle error.
 * }
 *
 * TINKSignatureKeyTemplate *tpl = [TINSignatureKeyTemplate initWithKeyTemplate:TINKEcdsaP521
 *                                                                        error:&error];
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
@interface TINKSignatureKeyTemplate : TINKKeyTemplate

- (nullable instancetype)init
    __attribute__((unavailable("Use -initWithKeyTemplate:error: instead.")));

/**
 * Creates a TINKSignatureKeyTemplate that can be used to generate signature keysets.
 *
 * @param keyTemplate The signature key template to use.
 * @param error       If non-nil it will be populated with a descriptive error when the operation
 *                    fails.
 * @return            A TINKSignatureKeyTemplate or nil in case of error.
 */
- (nullable instancetype)initWithKeyTemplate:(TINKSignatureKeyTemplates)keyTemplate
                                       error:(NSError **)error NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
