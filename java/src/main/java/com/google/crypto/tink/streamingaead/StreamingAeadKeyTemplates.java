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
 * Pre-generated {@code KeyTemplate} for {@code StreamingAead} keys. One can use these templates to
 * generate new {@code Keyset} with {@code KeysetHandle}. To generate a new keyset that contains a
 * single {@code AesGcmHkdfStreamingKey}, one can do:
 *
 * <pre>
 *   Config.register(StreamingAeadConfig.TINK_1_1_0);
 *   KeysetHandle handle =
 *       KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_GCM_HKDF_STREAMING);
 *   StreamingAead streamingAead = StreamingAeadFactory.getPrimitive(handle);
 * </pre>
 */
public final class StreamingAeadKeyTemplates {

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesGcmHkdfStreamingKey} with the
   * following parameters:
   *   - AES key size: 16 bytes
   *   - AES IV size: 16 bytes
   *   - HMAC tag size: 16 bytes
   *   - Ciphertext segment size: 4096
   */
  public static final KeyTemplate AES128_CTR_HMAC_STREAMING =
      createAesCtrHmacStreamingKeyTemplate(16, 16, 16, 4096);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesGcmHkdfStreamingKey} with the
   * following parameters:
   *   - AES key size: 32 bytes
   *   - AES IV size: 16 bytes
   *   - HMAC tag size: 32 bytes
   *   - Ciphertext segment size: 4096
   */
  public static final KeyTemplate AES256_CTR_HMAC_STREAMING =
      createAesCtrHmacStreamingKeyTemplate(32, 16, 32, 4096);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesGcmHkdfStreamingKey} with the
   * following parameters:
   *   - AES key size: 16 bytes
   *   - AES IV size: 16 bytes
   *   - Ciphertext segment size: 4096
   */
  public static final KeyTemplate AES128_GCM_HKDF_STREAMING =
      createAesGcmHkdfStreamingKeyTemplate(16, 16, 4096);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesGcmHkdfStreamingKey} with the
   * following parameters:
   *   - AES key size: 32 bytes
   *   - AES IV size: 16 bytes
   *   - Ciphertext segment size: 4096
   */
  public static final KeyTemplate AES256_GCM_HKDF_STREAMING =
      createAesGcmHkdfStreamingKeyTemplate(32, 16, 4096);

  /**
   * @return a {@code KeyTemplate} containing a {@code AesCtrHmacStreamingKeyFormat} with some
   *     specified parameters.
   */
  public static KeyTemplate createAesCtrHmacStreamingKeyTemplate(
      int keySize, int ivSize, int tagSize, int ciphertextSegmentSize) {
    HmacParams hmacParams =
        HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(tagSize).build();
    AesCtrHmacStreamingParams params =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(ciphertextSegmentSize)
            .setDerivedKeySize(keySize)
            .setHkdfHashType(HashType.SHA256)
            .setHmacParams(hmacParams)
            .build();
    AesCtrHmacStreamingKeyFormat format =
        AesCtrHmacStreamingKeyFormat.newBuilder().setParams(params).setKeySize(ivSize).build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesCtrHmacStreamingKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
  }

  /**
   * @return a {@code KeyTemplate} containing a {@code AesGcmHkdfStreamingKeyFormat} with some
   *     specified parameters.
   */
  public static KeyTemplate createAesGcmHkdfStreamingKeyTemplate(
      int keySize, int ivSize, int ciphertextSegmentSize) {
    AesGcmHkdfStreamingParams params =
        AesGcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(ciphertextSegmentSize)
            .setDerivedKeySize(keySize)
            .setHkdfHashType(HashType.SHA256)
            .build();
    AesGcmHkdfStreamingKeyFormat format =
        AesGcmHkdfStreamingKeyFormat.newBuilder().setParams(params).setKeySize(ivSize).build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesGcmHkdfStreamingKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.RAW)
        .build();
  }
}
