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

package com.google.crypto.tink.aead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

/**
 * Pre-generated {@link KeyTemplate} for {@link com.google.crypto.tink.Aead} keys.
 *
 * <p>Note: if you want to keep dependencies small, consider inlining the constants here.
 */
public final class PredefinedAeadParameters {
  /**
   * A {@link Parameters} object for generating new instances of {@link AesGcmKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   * </ul>
   *
   * <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance generated
   * by this key template does not support associated data. It might not work at all in older
   * versions.
   */
  public static final AesGcmParameters AES128_GCM =
      exceptionIsBug(
          () ->
              AesGcmParameters.builder()
                  .setIvSizeBytes(12)
                  .setKeySizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesGcmKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   * </ul>
   *
   * <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance generated
   * by this key template does not support associated data. It might not work at all in older
   * versions.
   */
  public static final AesGcmParameters AES256_GCM =
      exceptionIsBug(
          () ->
              AesGcmParameters.builder()
                  .setIvSizeBytes(12)
                  .setKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setVariant(AesGcmParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesEaxKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   *   <li>IV size: 16 bytes
   * </ul>
   */
  public static final AesEaxParameters AES128_EAX =
      exceptionIsBug(
          () ->
              AesEaxParameters.builder()
                  .setIvSizeBytes(16)
                  .setKeySizeBytes(16)
                  .setTagSizeBytes(16)
                  .setVariant(AesEaxParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesEaxKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>IV size: 16 bytes
   * </ul>
   */
  public static final AesEaxParameters AES256_EAX =
      exceptionIsBug(
          () ->
              AesEaxParameters.builder()
                  .setIvSizeBytes(16)
                  .setKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setVariant(AesEaxParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesCtrHmacAeadKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>AES key size: 16 bytes
   *   <li>AES CTR IV size: 16 byte
   *   <li>HMAC key size: 32 bytes
   *   <li>HMAC tag size: 16 bytes
   *   <li>HMAC hash function: SHA256
   * </ul>
   */
  public static final AesCtrHmacAeadParameters AES128_CTR_HMAC_SHA256 =
      exceptionIsBug(
          () ->
              AesCtrHmacAeadParameters.builder()
                  .setAesKeySizeBytes(16)
                  .setHmacKeySizeBytes(32)
                  .setTagSizeBytes(16)
                  .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                  .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesCtrHmacAeadKey} with the
   * following parameters:
   *
   * <ul>
   *   <li>AES key size: 32 bytes
   *   <li>AES CTR IV size: 16 byte
   *   <li>HMAC key size: 32 bytes
   *   <li>HMAC tag size: 32 bytes
   *   <li>HMAC hash function: SHA256
   * </ul>
   */
  public static final AesCtrHmacAeadParameters AES256_CTR_HMAC_SHA256 =
      exceptionIsBug(
          () ->
              AesCtrHmacAeadParameters.builder()
                  .setAesKeySizeBytes(32)
                  .setHmacKeySizeBytes(32)
                  .setTagSizeBytes(32)
                  .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                  .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                  .build());

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.ChaCha20Poly1305Key}.
   */
  public static final ChaCha20Poly1305Parameters CHACHA20_POLY1305 =
      ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.XChaCha20Poly1305Key}.
   */
  public static final XChaCha20Poly1305Parameters XCHACHA20_POLY1305 =
      XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);

  private PredefinedAeadParameters() {}
}
