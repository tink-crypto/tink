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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesEaxParameters.Variant;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.Bytes;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesEaxJce and its key manager. */
@RunWith(Theories.class)
public class AesEaxKeyManagerTest {
  @Before
  public void register() throws Exception {
    AeadConfig.register();
  }

  private static class PublicTestVector {
    String name;
    public byte[] keyValue;
    public byte[] plaintext;
    public byte[] aad;
    public byte[] iv;
    public byte[] ciphertext;
    public byte[] tag;

    public PublicTestVector(
        String name,
        String keyValue,
        String plaintext,
        String aad,
        String iv,
        String ciphertext,
        String tag) {
      try {
        this.name = name;
        this.keyValue = Hex.decode(keyValue);
        this.plaintext = Hex.decode(plaintext);
        this.aad = Hex.decode(aad);
        this.iv = Hex.decode(iv);
        this.ciphertext = Hex.decode(ciphertext);
        this.tag = Hex.decode(tag);
      } catch (Exception ignored) {
        // Ignored
      }
    }
  }

  // Test vectors from
  // http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf.
  PublicTestVector[] publicTestVectors = {
    new PublicTestVector(
        "Test Case 1",
        "233952dee4d5ed5f9b9c6d6ff80ff478",
        "",
        "6bfb914fd07eae6b",
        "62ec67f9c3a4a407fcb2a8c49031a8b3",
        "",
        "e037830e8389f27b025a2d6527e79d01"),
    new PublicTestVector(
        "Test Case 2",
        "91945d3f4dcbee0bf45ef52255f095a4",
        "f7fb",
        "fa3bfd4806eb53fa",
        "becaf043b0a23d843194ba972c66debd",
        "19dd",
        "5c4c9331049d0bdab0277408f67967e5"),
    new PublicTestVector(
        "Test Case 3",
        "01f74ad64077f2e704c0f60ada3dd523",
        "1a47cb4933",
        "234a3463c1264ac6",
        "70c3db4f0d26368400a10ed05d2bff5e",
        "d851d5bae0",
        "3a59f238a23e39199dc9266626c40f80"),
    new PublicTestVector(
        "Test Case 4",
        "d07cf6cbb7f313bdde66b727afd3c5e8",
        "481c9e39b1",
        "33cce2eabff5a79d",
        "8408dfff3c1a2b1292dc199e46b7d617",
        "632a9d131a",
        "d4c168a4225d8e1ff755939974a7bede"),
    new PublicTestVector(
        "Test Case 5",
        "35b6d0580005bbc12b0587124557d2c2",
        "40d0c07da5e4",
        "aeb96eaebe2970e9",
        "fdb6b06676eedc5c61d74276e1f8e816",
        "071dfe16c675",
        "cb0677e536f73afe6a14b74ee49844dd"),
    new PublicTestVector(
        "Test Case 6",
        "bd8e6e11475e60b268784c38c62feb22",
        "4de3b35c3fc039245bd1fb7d",
        "d4482d1ca78dce0f",
        "6eac5c93072d8e8513f750935e46da1b",
        "835bb4f15d743e350e728414",
        "abb8644fd6ccb86947c5e10590210a4f"),
    new PublicTestVector(
        "Test Case 7",
        "7c77d6e813bed5ac98baa417477a2e7d",
        "8b0a79306c9ce7ed99dae4f87f8dd61636",
        "65d2017990d62528",
        "1a8c98dcd73d38393b2bf1569deefc19",
        "02083e3979da014812f59f11d52630da30",
        "137327d10649b0aa6e1c181db617d7f2"),
    new PublicTestVector(
        "Test Case 8",
        "5fff20cafab119ca2fc73549e20f5b0d",
        "1bda122bce8a8dbaf1877d962b8592dd2d56",
        "54b9f04e6a09189a",
        "dde59b97d722156d4d9aff2bc7559826",
        "2ec47b2c4954a489afc7ba4897edcdae8cc3",
        "3b60450599bd02c96382902aef7f832a"),
    new PublicTestVector(
        "Test Case 9",
        "a4a4782bcffd3ec5e7ef6d8c34a56123",
        "6cf36720872b8513f6eab1a8a44438d5ef11",
        "899a175897561d7e",
        "b781fcf2f75fa5a8de97a9ca48e522ec",
        "0de18fd0fdd91e7af19f1d8ee8733938b1e8",
        "e7f6d2231618102fdb7fe55ff1991700"),
    new PublicTestVector(
        "Test Case 10",
        "8395fcf1e95bebd697bd010bc766aac3",
        "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7",
        "126735fcc320d25a",
        "22e7add93cfc6393c57ec0b3c17d6b44",
        "cb8920f87a6c75cff39627b56e3ed197c552d295a7",
        "cfc46afc253b4652b1af3795b124ab6e"),
  };

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.AesEaxKey", Aead.class))
        .isNotNull();
  }

  @Test
  public void testPublicTestVectors() throws Exception {
    for (PublicTestVector t : publicTestVectors) {
      AesEaxParameters parameters =
          AesEaxParameters.builder()
              .setIvSizeBytes(t.iv.length)
              .setKeySizeBytes(t.keyValue.length)
              .setTagSizeBytes(t.tag.length)
              .setVariant(AesEaxParameters.Variant.NO_PREFIX)
              .build();
      AesEaxKey key =
          AesEaxKey.builder()
              .setParameters(parameters)
              .setKeyBytes(SecretBytes.copyFrom(t.keyValue, InsecureSecretKeyAccess.get()))
              .build();
      Aead aead =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(key).makePrimary().withRandomId())
              .build()
              .getPrimitive(Aead.class);
      try {
        byte[] ciphertext = Bytes.concat(t.iv, t.ciphertext, t.tag);
        byte[] plaintext = aead.decrypt(ciphertext, t.aad);
        assertArrayEquals(plaintext, t.plaintext);
      } catch (GeneralSecurityException e) {
        fail("Should not fail at " + t.name + ", but thrown exception " + e);
      }
    }
  }

  @Test
  public void testAes128EaxTemplate() throws Exception {
    KeyTemplate template = AesEaxKeyManager.aes128EaxTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesEaxParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(AesEaxParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes128EaxTemplate() throws Exception {
    KeyTemplate template = AesEaxKeyManager.rawAes128EaxTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesEaxParameters.builder()
                .setKeySizeBytes(16)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testAes256EaxTemplate() throws Exception {
    KeyTemplate template = AesEaxKeyManager.aes256EaxTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesEaxParameters.builder()
                .setKeySizeBytes(32)
                .setIvSizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(AesEaxParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes256EaxTemplate() throws Exception {
    KeyTemplate template = AesEaxKeyManager.rawAes256EaxTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesEaxParameters.builder()
                .setIvSizeBytes(16)
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .build());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = AesEaxKeyManager.aes128EaxTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesEaxKeyManager.rawAes128EaxTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesEaxKeyManager.aes256EaxTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesEaxKeyManager.rawAes256EaxTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "AES128_EAX", "AES128_EAX_RAW", "AES256_EAX", "AES256_EAX_RAW",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    Parameters p = AesEaxKeyManager.rawAes256EaxTemplate().toParameters();
    Key key = KeysetHandle.generateNew(p).getAt(0).getKey();
    for (int i = 0; i < 1000; ++i) {
      assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().equalsKey(key)).isFalse();
    }
  }

  @Test
  public void test_24byte_keyCreation_throws() throws Exception {
    // We currently disallow creation of AesEaxKeys with 24 bytes (Tink doesn't support using these
    // for consistency among the languages, so we also disallow creation at the moment).
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(24)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(Variant.NO_PREFIX)
            .build();
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(parameters));
  }

  @Test
  public void test_24byte_primitiveCreation_throws() throws Exception {
    // We currently disallow creation of AesEaxKeys with 24 bytes (Tink doesn't support using these
    // for consistency among the languages, so we also disallow creation at the moment).
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(24)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(Variant.NO_PREFIX)
            .build();
    AesEaxKey key =
        AesEaxKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(24))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).makePrimary().withRandomId())
            .build();
    assertThrows(GeneralSecurityException.class, () -> keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void getPrimitiveFromKeysetHandle() throws Exception {
    AesEaxParameters parameters =
        AesEaxParameters.builder()
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(Variant.TINK)
            .build();
    com.google.crypto.tink.aead.AesEaxKey key =
        com.google.crypto.tink.aead.AesEaxKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(16))
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = keysetHandle.getPrimitive(Aead.class);
    Aead directAead = AesEaxJce.create(key);

    assertThat(aead.decrypt(directAead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
    assertThat(directAead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }
}
