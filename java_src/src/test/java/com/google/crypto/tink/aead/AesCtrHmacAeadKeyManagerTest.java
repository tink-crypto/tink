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

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for AesCtrHmacAeadKeyManager. */
@RunWith(Theories.class)
public class AesCtrHmacAeadKeyManagerTest {
  private final AesCtrHmacAeadKeyManager manager = new AesCtrHmacAeadKeyManager();
  private final KeyTypeManager.KeyFactory<AesCtrHmacAeadKeyFormat, AesCtrHmacAeadKey> factory =
      manager.keyFactory();

  @Before
  public void register() throws Exception {
    AeadConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesCtrHmacAeadKeyFormat.getDefaultInstance()));
  }

  // Returns an AesCtrKeyFormat.Builder with valid parameters
  private static AesCtrKeyFormat.Builder createAesCtrKeyFormat() {
    return AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(16))
        .setKeySize(16);
  }

  // Returns an HmacParams.Builder with valid parameters
  private static HmacParams.Builder createHmacParams() {
    return HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32);
  }

  // Returns an HmacParams.Builder with valid parameters
  private static HmacKeyFormat.Builder createHmacKeyFormat() {
    return HmacKeyFormat.newBuilder().setParams(createHmacParams()).setKeySize(32);
  }

  // Returns an AesCtrHmacStreamingKeyFormat.Builder with valid parameters
  private static AesCtrHmacAeadKeyFormat.Builder createKeyFormat() {
    return AesCtrHmacAeadKeyFormat.newBuilder()
        .setAesCtrKeyFormat(createAesCtrKeyFormat())
        .setHmacKeyFormat(createHmacKeyFormat());
  }

  private static AesCtrHmacAeadKeyFormat createKeyFormatForKeySize(int keySize) {
    return AesCtrHmacAeadKeyFormat.newBuilder()
        .setAesCtrKeyFormat(
            AesCtrKeyFormat.newBuilder()
                .setKeySize(keySize)
                .setParams(AesCtrParams.newBuilder().setIvSize(16))
                .build())
        .setHmacKeyFormat(
            HmacKeyFormat.newBuilder()
                .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32).build())
                .setKeySize(keySize)
                .build())
        .build();
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    factory.validateKeyFormat(createKeyFormat().build());
  }

  @Test
  public void validateKeyFormat_keySizes() throws Exception {
    for (int keySize = 0; keySize < 42; ++keySize) {
      AesCtrHmacAeadKeyFormat format =
          createKeyFormat().setAesCtrKeyFormat(createAesCtrKeyFormat().setKeySize(keySize)).build();
      if (keySize == 16 || keySize == 32) {
        factory.validateKeyFormat(format);
      } else {
        assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
      }
    }
  }

  @Test
  public void validateKeyFormat_hmacKeySizes() throws Exception {
    for (int keySize = 0; keySize < 42; ++keySize) {
      AesCtrHmacAeadKeyFormat format =
          createKeyFormat().setHmacKeyFormat(createHmacKeyFormat().setKeySize(keySize)).build();
      if (keySize >= 16) {
        factory.validateKeyFormat(format);
      } else {
        assertThrows(
            "For key size" + keySize,
            GeneralSecurityException.class,
            () -> factory.validateKeyFormat(format));
      }
    }
  }

  @Test
  public void deriveKey_size32() throws Exception {
    final int keySize = 32;
    AesCtrHmacAeadKeyFormat keyFormat = createKeyFormatForKeySize(keySize);
    byte[] keyMaterial = Random.randBytes(100);

    AesCtrHmacAeadKey key = factory.deriveKey(keyFormat, new ByteArrayInputStream(keyMaterial));

    assertThat(key.getAesCtrKey().getKeyValue()).isNotEqualTo(key.getHmacKey().getKeyValue());
    assertThat(key.getAesCtrKey().getKeyValue())
        .isEqualTo(ByteString.copyFrom(keyMaterial, 0, keySize));
    assertThat(key.getHmacKey().getKeyValue())
        .isEqualTo(ByteString.copyFrom(keyMaterial, keySize, keySize));
  }

  @Test
  public void deriveKey_size16() throws Exception {
    final int keySize = 16;
    AesCtrHmacAeadKeyFormat keyFormat = createKeyFormatForKeySize(keySize);
    byte[] keyMaterial = Random.randBytes(100);

    AesCtrHmacAeadKey key = factory.deriveKey(keyFormat, new ByteArrayInputStream(keyMaterial));

    assertThat(key.getAesCtrKey().getKeyValue()).isNotEqualTo(key.getHmacKey().getKeyValue());
    assertThat(key.getAesCtrKey().getKeyValue())
        .isEqualTo(ByteString.copyFrom(keyMaterial, 0, keySize));
    assertThat(key.getHmacKey().getKeyValue())
        .isEqualTo(ByteString.copyFrom(keyMaterial, keySize, keySize));
  }

  @Test
  public void deriveKey_handlesDataFragmentationCorrectly() throws Exception {
    int keySize = 32;
    byte randomness = 4;
    AesCtrHmacAeadKeyFormat keyFormat = createKeyFormatForKeySize(keySize);
    InputStream fragmentedInputStream =
        new InputStream() {
          @Override
          public int read() {
            return 0;
          }

          @Override
          // Will fill one byte per each `read` call, see:
          // google3/third_party/tink/java_src/src/main/java/com/google/crypto/tink/internal/KeyTypeManager.java;l=255;rcl=531814261.
          public int read(byte[] b, int off, int len) {
            b[off] = randomness;
            return 1;
          }
        };

    AesCtrHmacAeadKey key = factory.deriveKey(keyFormat, fragmentedInputStream);

    assertThat(key.getAesCtrKey().getKeyValue()).hasSize(keySize);
    assertThat(key.getHmacKey().getKeyValue()).hasSize(keySize);
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getAesCtrKey().getKeyValue().byteAt(i)).isEqualTo(randomness);
      assertThat(key.getHmacKey().getKeyValue().byteAt(i)).isEqualTo(randomness);
    }
  }

  @Test
  public void deriveKey_notEnoughAesCtrKeyMaterial_throws() throws Exception {
    final int keySize = 32;
    AesCtrHmacAeadKeyFormat keyFormat = createKeyFormatForKeySize(keySize);
    byte[] keyMaterial = Random.randBytes(keySize - 1);

    assertThrows(
        GeneralSecurityException.class,
        () -> factory.deriveKey(keyFormat, new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void deriveKey_notEnoughHmacKeyMaterial_throws() throws Exception {
    final int keySize = 32;
    AesCtrHmacAeadKeyFormat keyFormat = createKeyFormatForKeySize(keySize);
    byte[] keyMaterial = Random.randBytes(keySize + keySize - 1);

    assertThrows(
        GeneralSecurityException.class,
        () -> factory.deriveKey(keyFormat, new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void deriveKey_badVersion_throws() throws Exception {
    final int keySize = 32;
    AesCtrHmacAeadKeyFormat keyFormat =
        AesCtrHmacAeadKeyFormat.newBuilder()
            .setAesCtrKeyFormat(
                AesCtrKeyFormat.newBuilder()
                    .setKeySize(keySize)
                    .setParams(AesCtrParams.newBuilder().setIvSize(16))
                    .build())
            .setHmacKeyFormat(
                HmacKeyFormat.newBuilder()
                    .setVersion(1)
                    .setParams(
                        HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32).build())
                    .setKeySize(keySize)
                    .build())
            .build();
    byte[] keyMaterial = Random.randBytes(keySize + keySize);

    assertThrows(
        GeneralSecurityException.class,
        () -> factory.deriveKey(keyFormat, new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void deriveKey_justEnoughKeyMaterial() throws Exception {
    final int keySize = 32;
    AesCtrHmacAeadKeyFormat keyFormat =
        AesCtrHmacAeadKeyFormat.newBuilder()
            .setAesCtrKeyFormat(
                AesCtrKeyFormat.newBuilder()
                    .setKeySize(keySize)
                    .setParams(AesCtrParams.newBuilder().setIvSize(16))
                    .build())
            .setHmacKeyFormat(
                HmacKeyFormat.newBuilder()
                    .setParams(
                        HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32).build())
                    .setKeySize(keySize)
                    .build())
            .build();
    byte[] keyMaterial = Random.randBytes(keySize + keySize);

    AesCtrHmacAeadKey key = factory.deriveKey(keyFormat, new ByteArrayInputStream(keyMaterial));

    assertThat(key.getAesCtrKey().getKeyValue()).isNotEqualTo(key.getHmacKey().getKeyValue());
    assertThat(key.getAesCtrKey().getKeyValue())
        .isEqualTo(ByteString.copyFrom(keyMaterial, 0, keySize));
    assertThat(key.getHmacKey().getKeyValue())
        .isEqualTo(ByteString.copyFrom(keyMaterial, keySize, keySize));
  }

  @Test
  public void createKey_multipleTimes_distinctAesKeys() throws Exception {
    AesCtrHmacAeadKeyFormat format = createKeyFormat().build();
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 50;
    for (int i = 0; i < numTests; i++) {
      keys.add(Hex.encode(factory.createKey(format).getAesCtrKey().getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void createKey_multipleTimes_distinctHmacKeys() throws Exception {
    AesCtrHmacAeadKeyFormat format = createKeyFormat().build();
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 50;
    for (int i = 0; i < numTests; i++) {
      keys.add(Hex.encode(factory.createKey(format).getHmacKey().getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void getPrimitive() throws Exception {
    AesCtrHmacAeadKey key =
        factory.createKey(
            createKeyFormat()
                .setHmacKeyFormat(
                    createHmacKeyFormat().setParams(createHmacParams().setHash(HashType.SHA512)))
                .build());
    Aead managerAead = manager.getPrimitive(key, Aead.class);
    Aead directAead =
        EncryptThenAuthenticate.newAesCtrHmac(
            key.getAesCtrKey().getKeyValue().toByteArray(),
            key.getAesCtrKey().getParams().getIvSize(),
            "HMACSHA512",
            key.getHmacKey().getKeyValue().toByteArray(),
            key.getHmacKey().getParams().getTagSize());

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThat(directAead.decrypt(managerAead.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  @Test
  public void testAes128CtrHmacSha256Template() throws Exception {
    KeyTemplate template = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();
    assertThat(template.toParameters())
        .isEqualTo(
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(16)
                .setHmacKeySizeBytes(32)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testAes256CtrHmacSha256Template() throws Exception {
    KeyTemplate template = AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template();
    assertThat(template.toParameters())
        .isEqualTo(
            AesCtrHmacAeadParameters.builder()
                .setAesKeySizeBytes(32)
                .setHmacKeySizeBytes(32)
                .setIvSizeBytes(16)
                .setTagSizeBytes(32)
                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    AesCtrHmacAeadKeyManager manager = new AesCtrHmacAeadKeyManager();

    testKeyTemplateCompatible(manager, AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template());
    testKeyTemplateCompatible(manager, AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template());
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "AES128_CTR_HMAC_SHA256",
        "AES128_CTR_HMAC_SHA256_RAW",
        "AES256_CTR_HMAC_SHA256",
        "AES256_CTR_HMAC_SHA256_RAW",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }
}
