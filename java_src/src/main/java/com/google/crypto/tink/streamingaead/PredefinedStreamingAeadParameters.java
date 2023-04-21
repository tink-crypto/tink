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

package com.google.crypto.tink.streamingaead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

/**
 * Pre-generated {@link Parameter} objects for {@link com.google.crypto.tink.DeterministicAead}
 * keys.
 *
 * <p>Note: if you want to keep dependencies small, consider inlining the constants here.
 */
public final class PredefinedStreamingAeadParameters {
  /**
   * A {@link Parameters} object for generating new instances of {@link AesCtrHmacStreamingKey} with
   * the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 16 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-CTR derived keys: 16 bytes
   *   <li>Tag algo: HMAC-SHA256
   *   <li>Tag size: 32 bytes
   *   <li>Ciphertext segment size: 4096
   * </ul>
   */
  public static final AesCtrHmacStreamingParameters AES128_CTR_HMAC_SHA256_4KB =
      exceptionIsBug(
          () ->
              AesCtrHmacStreamingParameters.builder()
                  .setKeySizeBytes(16)
                  .setDerivedKeySizeBytes(16)
                  .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                  .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                  .setHmacTagSizeBytes(32)
                  .setCiphertextSegmentSizeBytes(4096)
                  .build());
  /**
   * A {@link Parameters} object for generating new instances of {@link AesCtrHmacStreamingKey} with
   * the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 16 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-CTR derived keys: 16 bytes
   *   <li>Tag algo: HMAC-SHA256
   *   <li>Tag size: 32 bytes
   *   <li>Ciphertext segment size: 1048576 bytes (1 MB)
   * </ul>
   */
  public static final AesCtrHmacStreamingParameters AES128_CTR_HMAC_SHA256_1MB =
      exceptionIsBug(
          () ->
              AesCtrHmacStreamingParameters.builder()
                  .setKeySizeBytes(16)
                  .setDerivedKeySizeBytes(16)
                  .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                  .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                  .setHmacTagSizeBytes(32)
                  .setCiphertextSegmentSizeBytes(1024 * 1024)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesCtrHmacStreamingKey} with
   * the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 32 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-CTR derived keys: 32 bytes
   *   <li>Tag algo: HMAC-SHA256
   *   <li>Tag size: 32 bytes
   *   <li>Ciphertext segment size: 4096
   * </ul>
   */
  public static final AesCtrHmacStreamingParameters AES256_CTR_HMAC_SHA256_4KB =
      exceptionIsBug(
          () ->
              AesCtrHmacStreamingParameters.builder()
                  .setKeySizeBytes(32)
                  .setDerivedKeySizeBytes(32)
                  .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                  .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                  .setHmacTagSizeBytes(32)
                  .setCiphertextSegmentSizeBytes(4096)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesCtrHmacStreamingKey} with
   * the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 32 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-CTR derived keys: 32 bytes
   *   <li>Tag algo: HMAC-SHA256
   *   <li>Tag size: 32 bytes
   *   <li>Ciphertext segment size: 1048576 bytes (1 MB)
   * </ul>
   */
  public static final AesCtrHmacStreamingParameters AES256_CTR_HMAC_SHA256_1MB =
      exceptionIsBug(
          () ->
              AesCtrHmacStreamingParameters.builder()
                  .setKeySizeBytes(32)
                  .setDerivedKeySizeBytes(32)
                  .setHkdfHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                  .setHmacHashType(AesCtrHmacStreamingParameters.HashType.SHA256)
                  .setHmacTagSizeBytes(32)
                  .setCiphertextSegmentSizeBytes(1024 * 1024)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesGcmHkdfStreamingKey} with
   * the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 16 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-GCM derived keys: 16 bytes
   *   <li>Ciphertext segment size: 4096 bytes
   * </ul>
   */
  public static final AesGcmHkdfStreamingParameters AES128_GCM_HKDF_4KB =
      exceptionIsBug(
          () ->
              AesGcmHkdfStreamingParameters.builder()
                  .setKeySizeBytes(16)
                  .setDerivedAesGcmKeySizeBytes(16)
                  .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                  .setCiphertextSegmentSizeBytes(4096)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesGcmHkdfStreamingKey} with
   * the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 16 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-GCM derived keys: 16 bytes
   *   <li>Ciphertext segment size: 1048576 bytes (1 MB)
   * </ul>
   */
  public static final AesGcmHkdfStreamingParameters AES128_GCM_HKDF_1MB =
      exceptionIsBug(
          () ->
              AesGcmHkdfStreamingParameters.builder()
                  .setKeySizeBytes(16)
                  .setDerivedAesGcmKeySizeBytes(16)
                  .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                  .setCiphertextSegmentSizeBytes(1024 * 1024)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesGcmHkdfStreamingKey} with
   * the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 32 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-GCM derived keys: 32 bytes
   *   <li>Ciphertext segment size: 4096 bytes (4 KB)
   * </ul>
   */
  public static final AesGcmHkdfStreamingParameters AES256_GCM_HKDF_4KB =
      exceptionIsBug(
          () ->
              AesGcmHkdfStreamingParameters.builder()
                  .setKeySizeBytes(32)
                  .setDerivedAesGcmKeySizeBytes(32)
                  .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                  .setCiphertextSegmentSizeBytes(4096)
                  .build());

  /**
   * A {@link Parameters} object for generating new instances of {@link AesGcmHkdfStreamingKey} with
   * the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 32 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-GCM derived keys: 32 bytes
   *   <li>Ciphertext segment size: 1048576 bytes (1 MB)
   * </ul>
   */
  public static final AesGcmHkdfStreamingParameters AES256_GCM_HKDF_1MB =
      exceptionIsBug(
          () ->
              AesGcmHkdfStreamingParameters.builder()
                  .setKeySizeBytes(32)
                  .setDerivedAesGcmKeySizeBytes(32)
                  .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                  .setCiphertextSegmentSizeBytes(1024 * 1024)
                  .build());

  private PredefinedStreamingAeadParameters() {}
}
