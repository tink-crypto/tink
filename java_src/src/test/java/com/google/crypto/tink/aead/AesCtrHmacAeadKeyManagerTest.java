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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AesCtrHmacAeadKeyManager. */
@RunWith(JUnit4.class)
public class AesCtrHmacAeadKeyManagerTest {
  private final AesCtrHmacAeadKeyManager manager = new AesCtrHmacAeadKeyManager();
  private final KeyTypeManager.KeyFactory<AesCtrHmacAeadKeyFormat, AesCtrHmacAeadKey> factory =
      manager.keyFactory();

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
  public void createKey_multipleTimes_distinctAesKeys() throws Exception {
    AesCtrHmacAeadKeyFormat format = createKeyFormat().build();
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 50;
    for (int i = 0; i < numTests; i++) {
      keys.add(
          TestUtil.hexEncode(factory.createKey(format).getAesCtrKey().getKeyValue().toByteArray()));
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
      keys.add(
          TestUtil.hexEncode(factory.createKey(format).getHmacKey().getKeyValue().toByteArray()));
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
    assertEquals(new AesCtrHmacAeadKeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(KeyTemplate.OutputPrefixType.TINK, template.getOutputPrefixType());
    AesCtrHmacAeadKeyFormat format =
        AesCtrHmacAeadKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertTrue(format.hasAesCtrKeyFormat());
    assertTrue(format.getAesCtrKeyFormat().hasParams());
    assertEquals(16, format.getAesCtrKeyFormat().getKeySize());
    assertEquals(16, format.getAesCtrKeyFormat().getParams().getIvSize());

    assertTrue(format.hasHmacKeyFormat());
    assertTrue(format.getHmacKeyFormat().hasParams());
    assertEquals(32, format.getHmacKeyFormat().getKeySize());
    assertEquals(16, format.getHmacKeyFormat().getParams().getTagSize());
    assertEquals(HashType.SHA256, format.getHmacKeyFormat().getParams().getHash());
  }

  @Test
  public void testAes256CtrHmacSha256Template() throws Exception {
    KeyTemplate template = AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template();
    assertEquals(new AesCtrHmacAeadKeyManager().getKeyType(), template.getTypeUrl());
    assertEquals(KeyTemplate.OutputPrefixType.TINK, template.getOutputPrefixType());
    AesCtrHmacAeadKeyFormat format =
        AesCtrHmacAeadKeyFormat.parseFrom(
            template.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertTrue(format.hasAesCtrKeyFormat());
    assertTrue(format.getAesCtrKeyFormat().hasParams());
    assertEquals(32, format.getAesCtrKeyFormat().getKeySize());
    assertEquals(16, format.getAesCtrKeyFormat().getParams().getIvSize());

    assertTrue(format.hasHmacKeyFormat());
    assertTrue(format.getHmacKeyFormat().hasParams());
    assertEquals(32, format.getHmacKeyFormat().getKeySize());
    assertEquals(32, format.getHmacKeyFormat().getParams().getTagSize());
    assertEquals(HashType.SHA256, format.getHmacKeyFormat().getParams().getHash());
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    AesCtrHmacAeadKeyManager manager = new AesCtrHmacAeadKeyManager();

    testKeyTemplateCompatible(manager, AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template());
    testKeyTemplateCompatible(manager, AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template());
  }

  @Test
  public void testKeyFormats() throws Exception {
    factory.validateKeyFormat(factory.keyFormats().get("AES128_CTR_HMAC_SHA256").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("AES128_CTR_HMAC_SHA256_RAW").keyFormat);

    factory.validateKeyFormat(factory.keyFormats().get("AES256_CTR_HMAC_SHA256").keyFormat);
    factory.validateKeyFormat(factory.keyFormats().get("AES256_CTR_HMAC_SHA256_RAW").keyFormat);
  }
}
