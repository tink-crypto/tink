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

package com.google.crypto.tink.prf;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

/**
 * Predefined {@link Parameters} for PRF-Keys.
 *
 * <p>Note: if you want to keep dependencies small, consider inlining the constants here.
 */
public final class PredefinedPrfParameters {

  private PredefinedPrfParameters() {}

  /**
   * A {@link Parameters} object for generating new instances of {@link HkdfPrfKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>HMAC key size: 32 bytes
   *   <li>Salt: empty
   * </ul>
   */
  public static final HkdfPrfParameters HKDF_SHA256 =
      exceptionIsBug(
          () ->
              HkdfPrfParameters.builder()
                  .setKeySizeBytes(32)
                  .setHashType(HkdfPrfParameters.HashType.SHA256)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link HmacPrfKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>HMAC key size: 32 bytes
   * </ul>
   */
  public static final HmacPrfParameters HMAC_SHA256_PRF =
      exceptionIsBug(
          () ->
              HmacPrfParameters.builder()
                  .setKeySizeBytes(32)
                  .setHashType(HmacPrfParameters.HashType.SHA256)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link HmacPrfKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>Hash function: SHA512
   *   <li>HMAC key size: 64 bytes
   * </ul>
   */
  public static final HmacPrfParameters HMAC_SHA512_PRF =
      exceptionIsBug(
          () ->
              HmacPrfParameters.builder()
                  .setKeySizeBytes(64)
                  .setHashType(HmacPrfParameters.HashType.SHA512)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesCmacKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>HMAC key size: 32 bytes
   * </ul>
   */
  public static final AesCmacPrfParameters AES_CMAC_PRF =
      exceptionIsBug(() -> AesCmacPrfParameters.create(32));
}
