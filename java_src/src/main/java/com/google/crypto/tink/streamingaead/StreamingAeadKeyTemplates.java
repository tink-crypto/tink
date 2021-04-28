// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat;
import com.google.crypto.tink.proto.AesCtrHmacStreamingParams;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;

/**
 * Pre-generated {@link KeyTemplate} for {@link com.google.crypto.tink.StreamingAead} keys.
 *
 * <p>One can use these templates to generate new {@link com.google.crypto.tink.proto.Keyset} with
 * {@code KeysetHandle}. To generate a new keyset that contains a {@link AesGcmHkdfStreamingKey},
 * one can do:
 *
 * <pre>{@code
 * Config.register(StreamingAeadConfig.TINK_1_0_0);
 * KeysetHandle handle = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_GCM_HKDF_4KB);
 * StreamingAead ags = handle.getPrimitive(StreamingAead.class);
 * }</pre>
 *
 * @since 1.1.0
 * @deprecated use {@link com.google.crypto.tink.KeyTemplates#get}, e.g.,
 *     KeyTemplates.get("AES256_GCM_HKDF_1MB")
 */
@Deprecated
public final class StreamingAeadKeyTemplates {
  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesCtrHmacStreamingKey} with the following parameters:
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
  public static final KeyTemplate AES128_CTR_HMAC_SHA256_4KB =
      createAesCtrHmacStreamingKeyTemplate(16, HashType.SHA256, 16, HashType.SHA256, 32, 4096);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesCtrHmacStreamingKey} with the following parameters:
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
  public static final KeyTemplate AES128_CTR_HMAC_SHA256_1MB =
      createAesCtrHmacStreamingKeyTemplate(16, HashType.SHA256, 16, HashType.SHA256, 32, 1048576);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesCtrHmacStreamingKey} with the following parameters:
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
  public static final KeyTemplate AES256_CTR_HMAC_SHA256_4KB =
      createAesCtrHmacStreamingKeyTemplate(32, HashType.SHA256, 32, HashType.SHA256, 32, 4096);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesCtrHmacStreamingKey} with the following parameters:
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
  public static final KeyTemplate AES256_CTR_HMAC_SHA256_1MB =
      createAesCtrHmacStreamingKeyTemplate(32, HashType.SHA256, 32, HashType.SHA256, 32, 1048576);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesGcmHkdfStreamingKey} with the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 16 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-GCM derived keys: 16 bytes
   *   <li>Ciphertext segment size: 4096 bytes
   * </ul>
   */
  public static final KeyTemplate AES128_GCM_HKDF_4KB =
      createAesGcmHkdfStreamingKeyTemplate(16, HashType.SHA256, 16, 4096);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesGcmHkdfStreamingKey} with the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 16 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-GCM derived keys: 16 bytes
   *   <li>Ciphertext segment size: 1048576 bytes (1 MB)
   * </ul>
   */
  public static final KeyTemplate AES128_GCM_HKDF_1MB =
      createAesGcmHkdfStreamingKeyTemplate(16, HashType.SHA256, 16, 1048576);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesGcmHkdfStreamingKey} with the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 32 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-GCM derived keys: 32 bytes
   *   <li>Ciphertext segment size: 4096 bytes
   * </ul>
   */
  public static final KeyTemplate AES256_GCM_HKDF_4KB =
      createAesGcmHkdfStreamingKeyTemplate(32, HashType.SHA256, 32, 4096);

  /**
   * A {@link KeyTemplate} that generates new instances of {@link
   * com.google.crypto.tink.proto.AesGcmHkdfStreamingKey} with the following parameters:
   *
   * <ul>
   *   <li>Size of the main key: 32 bytes
   *   <li>HKDF algo: HMAC-SHA256
   *   <li>Size of AES-GCM derived keys: 32 bytes
   *   <li>Ciphertext segment size: 1048576 bytes (1 MB)
   * </ul>
   */
  public static final KeyTemplate AES256_GCM_HKDF_1MB =
      createAesGcmHkdfStreamingKeyTemplate(32, HashType.SHA256, 32, 1048576);

  /**
   * @return a {@link KeyTemplate} containing a {@link AesCtrHmacStreamingKeyFormat} with some
   *     specified parameters.
   */
  public static KeyTemplate createAesCtrHmacStreamingKeyTemplate(
      int mainKeySize,
      HashType hkdfHashType,
      int derivedKeySize,
      HashType macHashType,
      int tagSize,
      int ciphertextSegmentSize) {
    HmacParams hmacParams = HmacParams.newBuilder()
        .setHash(macHashType)
        .setTagSize(tagSize)
        .build();
    AesCtrHmacStreamingParams params =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(ciphertextSegmentSize)
            .setDerivedKeySize(derivedKeySize)
            .setHkdfHashType(hkdfHashType)
            .setHmacParams(hmacParams)
            .build();
    AesCtrHmacStreamingKeyFormat format = AesCtrHmacStreamingKeyFormat.newBuilder()
        .setParams(params)
        .setKeySize(mainKeySize)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(new AesCtrHmacStreamingKeyManager().getKeyType())
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
  }

  /**
   * @return a {@code KeyTemplate} containing a {@code AesGcmHkdfStreamingKeyFormat}
   *     with some specified parameters.
   */
  public static KeyTemplate createAesGcmHkdfStreamingKeyTemplate(
      int mainKeySize, HashType hkdfHashType, int derivedKeySize, int ciphertextSegmentSize) {
    AesGcmHkdfStreamingParams keyParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(ciphertextSegmentSize)
            .setDerivedKeySize(derivedKeySize)
            .setHkdfHashType(hkdfHashType)
            .build();
    AesGcmHkdfStreamingKeyFormat format =
        AesGcmHkdfStreamingKeyFormat.newBuilder()
            .setKeySize(mainKeySize)
            .setParams(keyParams)
            .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(new AesGcmHkdfStreamingKeyManager().getKeyType())
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
  }

  private StreamingAeadKeyTemplates() {}
}
