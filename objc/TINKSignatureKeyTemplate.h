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
   * `EcdsaPrivateKey` with the following parameters:
   *   - EC curve: NIST P-256
   *   - hash function: SHA256
   *   - signature: DER
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP256 = 1,

  /**
   * `EcdsaPrivateKey` with the following parameters:
   *   - EC curve: NIST P-384
   *   - hash function: SHA512
   *   - signature: DER
   *   - OutputPrefixType: TINK
   *
   * Deprecated. Use TINKEcdsaP384Sha512 instead.
   */
  TINKEcdsaP384 = 2,

  /**
   * `EcdsaPrivateKey` with the following parameters:
   *   - EC curve: NIST P-521
   *   - hash function: SHA512
   *   - signature: DER
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP521 = 3,

  /**
   * `EcdsaPrivateKey` with the following parameters:
   *   - EC curve: NIST P-256
   *   - hash function: SHA256
   *   - signature: IEEE P1363
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP256Ieee = 4,

  /**
   * `EcdsaPrivateKey` with the following parameters:
   *   - EC curve: NIST P-384
   *   - hash function: SHA512
   *   - signature: IEEE P1363
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP384Ieee = 5,

  /**
   * `EcdsaPrivateKey` with the following parameters:
   *   - EC curve: NIST P-521
   *   - hash function: SHA512
   *   - signature: IEEE P1363
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP521Ieee = 6,

  /**
   * `RsaSsaPkcs1PrivateKey` with the following parameters:
   *   - Modulus size in bits: 3072.
   *   - Hash function: SHA256.
   *   - Public Exponent: 65537 (aka F4).
   *   - OutputPrefixType: TINK
   */
  TINKRsaSsaPkcs13072Sha256F4 = 7,

  /**
   * `RsaSsaPkcs1PrivateKey` with the following parameters:
   *   - Modulus size in bits: 4096.
   *   - Hash function: SHA512.
   *   - Public Exponent: 65537 (aka F4).
   *   - OutputPrefixType: TINK
   */
  TINKRsaSsaPkcs14096Sha512F4 = 8,

  /**
   * `RsaSsaPssPrivateKey` with the following parameters:
   *   - Modulus size in bits: 3072.
   *   - Signature hash: SHA256.
   *   - MGF1 hash: SHA256.
   *   - Salt length: 32 (i.e., SHA256's output length).
   *   - Public Exponent: 65537 (aka F4).
   *   - OutputPrefixType: TINK
   */
  TINKRsaSsaPss3072Sha256Sha256F4 = 9,

  /**
   * `RsaSsaPssPrivateKey` with the following parameters:
   *   - Modulus size in bits: 4096.
   *   - Signature hash: SHA512.
   *   - MGF1 hash: SHA512.
   *   - Salt length: 64 (i.e., SHA512's output length).
   *   - Public Exponent: 65537 (aka F4).
   *   - OutputPrefixType: TINK
   */
  TINKRsaSsaPss4096Sha512Sha512F4 = 10,

  /**
   * `Ed25519PrivateKey`.
   */
  TINKEd25519 = 11,

  /**
   * `EcdsaPrivateKey` with the following parameters:
   *   - EC curve: NIST P-384
   *   - hash function: SHA384
   *   - signature: DER
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP384Sha384 = 12,

  /**
   * `EcdsaPrivateKey` with the following parameters:
   *   - EC curve: NIST P-384
   *   - hash function: SHA512
   *   - signature: DER
   *   - OutputPrefixType: TINK
   */
  TINKEcdsaP384Sha512 = 13,
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

- (instancetype)init
    __attribute__((unavailable("Use -initWithKeyTemplate:error: instead.")));

/**
 * Creates a TINKSignatureKeyTemplate that can be used to generate signature keysets.
 *
 * @param keyTemplate The signature key template.
 * @param error       If non-nil it will be populated with a descriptive error when the operation
 *                    fails.
 * @return            A TINKSignatureKeyTemplate or nil in case of error.
 */
- (nullable instancetype)initWithKeyTemplate:(TINKSignatureKeyTemplates)keyTemplate
                                       error:(NSError **)error NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
