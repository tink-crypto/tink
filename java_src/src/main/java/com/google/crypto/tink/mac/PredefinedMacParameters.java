// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.mac;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

/**
 * Pre-defined {@link Parameter} objects for {@link com.google.crypto.tink.Mac}.
 *
 * <p>Note: if you want to keep dependencies small, consider inlining the constants here.
 */
public final class PredefinedMacParameters {
  /**
   * A {@link Parameters} object for generating new instances of {@link HmacKey} with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Tag size: 16 bytes
   *   <li>Hash function: SHA256
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final HmacParameters HMAC_SHA256_128BITTAG =
      exceptionIsBug(
          () ->
              HmacParameters.builder()
                  .setKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setVariant(HmacParameters.Variant.TINK)
                  .setHashType(HmacParameters.HashType.SHA256)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link HmacKey} with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Tag size: 32 bytes
   *   <li>Hash function: SHA256
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final HmacParameters HMAC_SHA256_256BITTAG =
      exceptionIsBug(
          () ->
              HmacParameters.builder()
                  .setKeySizeBytes(32)
                  .setTagSizeBytes(32)
                  .setVariant(HmacParameters.Variant.TINK)
                  .setHashType(HmacParameters.HashType.SHA256)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link HmacKey} with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 64 bytes
   *   <li>Tag size: 32 bytes
   *   <li>Hash function: SHA512
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final HmacParameters HMAC_SHA512_256BITTAG =
      exceptionIsBug(
          () ->
              HmacParameters.builder()
                  .setKeySizeBytes(64)
                  .setTagSizeBytes(32)
                  .setVariant(HmacParameters.Variant.TINK)
                  .setHashType(HmacParameters.HashType.SHA512)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link HmacKey} with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 64 bytes
   *   <li>Tag size: 64 bytes
   *   <li>Hash function: SHA512
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final HmacParameters HMAC_SHA512_512BITTAG =
      exceptionIsBug(
          () ->
              HmacParameters.builder()
                  .setKeySizeBytes(64)
                  .setTagSizeBytes(64)
                  .setVariant(HmacParameters.Variant.TINK)
                  .setHashType(HmacParameters.HashType.SHA512)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link CmacKey} with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Tag size: 16 bytes
   *   <li>OutputPrefixType: TINK
   * </ul>
   */
  public static final AesCmacParameters AES_CMAC =
      exceptionIsBug(
          () ->
              AesCmacParameters.builder()
                  .setKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setVariant(AesCmacParameters.Variant.TINK)
                  .build());

  private PredefinedMacParameters() {}
}
