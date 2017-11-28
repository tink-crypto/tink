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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.AesEaxParams;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.KmsAeadKeyFormat;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.proto.OutputPrefixType;

/**
 * Pre-generated {@code KeyTemplate} for {@code Aead} keys. One can use these templates
 * to generate new {@code Keyset} with {@code KeysetHandle}. To generate a new keyset
 * that contains a single {@code AesGcmKey}, one can do:
 * <pre>
 *   Config.register(AeadConfig.TINK_1_0_0);
 *   KeysetHandle handle = KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM);
 *   Aead aead = AeadFactory.getPrimitive(handle);
 * </pre>
 */
public final class AeadKeyTemplates {
  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesGcmKey} with the following
   * parameters:
   *   - Key size: 16 bytes
   */
  public static final KeyTemplate AES128_GCM = createAesGcmKeyTemplate(16);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesGcmKey} with the following
   * parameters:
   *   - Key size: 32 bytes
   */
  public static final KeyTemplate AES256_GCM = createAesGcmKeyTemplate(32);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesEaxKey} with the following
   * parameters:
   *   - Key size: 16 bytes
   *   - IV size: 16 bytes.
   */
  public static final KeyTemplate AES128_EAX = createAesEaxKeyTemplate(16, 16);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesEaxKey} with the following
   * parameters:
   *   - Key size: 32 bytes
   *   - IV size: 16 bytes
   */
  public static final KeyTemplate AES256_EAX = createAesEaxKeyTemplate(32, 16);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesCtrHmacAeadKey} with the
   * following parameters:
   *   - AES key size: 16 bytes
   *   - AES IV size: 16 bytes
   *   - HMAC key size: 32 bytes
   *   - HMAC tag size: 16 bytes
   *   - HMAC hash function: SHA256
   */
  public static final KeyTemplate AES128_CTR_HMAC_SHA256 =
      createAesCtrHmacAeadKeyTemplate(16, 16, 32, 16, HashType.SHA256);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code AesCtrHmacAeadKey} with the
   * following parameters:
   *   - AES key size: 32 bytes
   *   - AES IV size: 16 bytes
   *   - HMAC key size: 32 bytes
   *   - HMAC tag size: 32 bytes
   *   - HMAC hash function: SHA256
   */
  public static final KeyTemplate AES256_CTR_HMAC_SHA256 =
      createAesCtrHmacAeadKeyTemplate(32, 16, 32, 32, HashType.SHA256);

  /**
   * A {@code KeyTemplate} that generates new instances of {@code ChaCha20Poly1305Key}.
   */
  @Alpha
  public static final KeyTemplate CHACHA20_POLY1305 =
      KeyTemplate.newBuilder()
        .setTypeUrl(ChaCha20Poly1305KeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();

  /**
   * @return a {@code KeyTemplate} containing a {@code AesGcmKeyFormat} with some specified
   * parameters.
   */
  public static KeyTemplate createAesGcmKeyTemplate(int keySize) {
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder()
        .setKeySize(keySize)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesGcmKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * @return a {@code KeyTemplate} containing a {@code AesEaxKeyFormat} with some specified
   * parameters.
   */
  public static KeyTemplate createAesEaxKeyTemplate(int keySize, int ivSize) {
    AesEaxKeyFormat format = AesEaxKeyFormat.newBuilder()
        .setKeySize(keySize)
        .setParams(AesEaxParams.newBuilder().setIvSize(ivSize).build())
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesEaxKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * @return a {@code KeyTemplate} containing a {@code AesCtrHmacAeadKeyFormat} with some
   * specific parameters.
   */
  public static KeyTemplate createAesCtrHmacAeadKeyTemplate(int aesKeySize, int ivSize,
      int hmacKeySize, int tagSize, HashType hashType) {
    AesCtrKeyFormat aesCtrKeyFormat = AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(ivSize).build())
        .setKeySize(aesKeySize)
        .build();
    HmacKeyFormat hmacKeyFormat = HmacKeyFormat.newBuilder()
        .setParams(
            HmacParams.newBuilder().setHash(hashType).setTagSize(tagSize).build())
        .setKeySize(hmacKeySize)
        .build();
    AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.newBuilder()
        .setAesCtrKeyFormat(aesCtrKeyFormat)
        .setHmacKeyFormat(hmacKeyFormat)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(AesCtrHmacAeadKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * @return a new {@code KeyTemplate} that can generate a {@code KmsAeadKey} pointing to
   * {@code keyUri}.
   */
  public static KeyTemplate createKmsAeadKeyTemplate(String keyUri) {
    KmsAeadKeyFormat format = KmsAeadKeyFormat.newBuilder()
        .setKeyUri(keyUri)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(KmsAeadKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }

  /**
   * @return a new {@code KeyTemplate} that can generate a {@code KmsEnvelopeAeadKey} whose
   * KEK is pointing to {@code kekUri} and DEK template is {@code dekTemplate}.
   */
  public static KeyTemplate createKmsEnvelopeAeadKeyTemplate(
    String kekUri, KeyTemplate dekTemplate) {
    KmsEnvelopeAeadKeyFormat format = KmsEnvelopeAeadKeyFormat.newBuilder()
        .setDekTemplate(dekTemplate)
        .setKekUri(kekUri)
        .build();
    return KeyTemplate.newBuilder()
        .setValue(format.toByteString())
        .setTypeUrl(KmsEnvelopeAeadKeyManager.TYPE_URL)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();
  }
}
