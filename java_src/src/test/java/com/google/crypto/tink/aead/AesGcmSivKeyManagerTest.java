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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.AesGcmSivKey;
import com.google.crypto.tink.proto.AesGcmSivKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nullable;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Test for AesGcmSivKeyManagerTest. */
@RunWith(Theories.class)
public class AesGcmSivKeyManagerTest {
  private final AesGcmSivKeyManager manager = new AesGcmSivKeyManager();
  private final KeyTypeManager.KeyFactory<AesGcmSivKeyFormat, AesGcmSivKey> factory =
      manager.keyFactory();

  @Before
  public void setUp() throws Exception {
    try {
      Conscrypt.checkAvailability();
      Security.addProvider(Conscrypt.newProvider());
    } catch (Throwable cause) {
      // Ignore. This fails on android, in which case Conscrypt is already installed by default.
    }
    AeadConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmSivKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmSivKeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    factory.validateKeyFormat(AesGcmSivKeyFormat.newBuilder().setKeySize(16).build());
    factory.validateKeyFormat(AesGcmSivKeyFormat.newBuilder().setKeySize(32).build());
  }

  @Test
  public void validateKeyFormat_invalid() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmSivKeyFormat.newBuilder().setKeySize(1).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmSivKeyFormat.newBuilder().setKeySize(15).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmSivKeyFormat.newBuilder().setKeySize(17).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmSivKeyFormat.newBuilder().setKeySize(31).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmSivKeyFormat.newBuilder().setKeySize(33).build()));
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(AesGcmSivKeyFormat.newBuilder().setKeySize(64).build()));
  }

  @Test
  public void createKey_16Bytes() throws Exception {
    AesGcmSivKey key = factory.createKey(AesGcmSivKeyFormat.newBuilder().setKeySize(16).build());
    assertThat(key.getKeyValue()).hasSize(16);
  }

  @Test
  public void createKey_32Bytes() throws Exception {
    AesGcmSivKey key = factory.createKey(AesGcmSivKeyFormat.newBuilder().setKeySize(32).build());
    assertThat(key.getKeyValue()).hasSize(32);
  }

  @Test
  public void createKey_multipleTimes() throws Exception {
    AesGcmSivKeyFormat format = AesGcmSivKeyFormat.newBuilder().setKeySize(16).build();
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 50;
    for (int i = 0; i < numTests; i++) {
      keys.add(Hex.encode(factory.createKey(format).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void getPrimitive() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    AesGcmSivKey key = factory.createKey(AesGcmSivKeyFormat.newBuilder().setKeySize(16).build());
    Aead managerAead = manager.getPrimitive(key, Aead.class);
    Aead directAead = new AesGcmSiv(key.getKeyValue().toByteArray());

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    assertThat(directAead.decrypt(managerAead.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  @Test
  public void testCiphertextSize() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    AesGcmSivKey key = factory.createKey(AesGcmSivKeyFormat.newBuilder().setKeySize(32).build());
    Aead aead = new AesGcmSivKeyManager().getPrimitive(key, Aead.class);
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associatedData".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(ciphertext.length)
        .isEqualTo(12 /* IV_SIZE */ + plaintext.length + 16 /* TAG_SIZE */);
  }

  @Test
  public void testAes128GcmSivTemplate() throws Exception {
    KeyTemplate template = AesGcmSivKeyManager.aes128GcmSivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmSivParameters.builder()
                .setKeySizeBytes(16)
                .setVariant(AesGcmSivParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes128GcmSivTemplate() throws Exception {
    KeyTemplate template = AesGcmSivKeyManager.rawAes128GcmSivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmSivParameters.builder()
                .setKeySizeBytes(16)
                .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testAes256GcmSivTemplate() throws Exception {
    KeyTemplate template = AesGcmSivKeyManager.aes256GcmSivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmSivParameters.builder()
                .setKeySizeBytes(32)
                .setVariant(AesGcmSivParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes256GcmSivTemplate() throws Exception {
    KeyTemplate template = AesGcmSivKeyManager.rawAes256GcmSivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmSivParameters.builder()
                .setKeySizeBytes(32)
                .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                .build());
  }

  @Test
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = AesGcmSivKeyManager.aes128GcmSivTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmSivKeyManager.rawAes128GcmSivTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmSivKeyManager.aes256GcmSivTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesGcmSivKeyManager.rawAes256GcmSivTemplate().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {"AES128_GCM_SIV", "AES256_GCM_SIV", "AES256_GCM_SIV_RAW", "AES128_GCM_SIV_RAW"};

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Theory
  public void testCreateKeyFromRandomness(@FromDataPoints("templateNames") String templateName)
      throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    AesGcmSivParameters parameters =
        (AesGcmSivParameters) KeyTemplates.get(templateName).toParameters();
    com.google.crypto.tink.aead.AesGcmSivKey key =
        AesGcmSivKeyManager.createAesGcmSivKeyFromRandomness(
            parameters,
            new ByteArrayInputStream(keyMaterial),
            parameters.hasIdRequirement() ? 123 : null,
            InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.aead.AesGcmSivKey.builder()
            .setParameters(parameters)
            .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
            .setKeyBytes(SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
        };
    com.google.crypto.tink.aead.AesGcmSivKey key =
        AesGcmSivKeyManager.createAesGcmSivKeyFromRandomness(
            parameters,
            SlowInputStream.copyFrom(keyMaterial),
            parameters.hasIdRequirement() ? 123 : null,
            InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.aead.AesGcmSivKey.builder()
            .setParameters(parameters)
            .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
            .setKeyBytes(SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testEncryptDecrypt_works() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    com.google.crypto.tink.aead.AesGcmSivKey aesGcmSivKey =
        com.google.crypto.tink.aead.AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("5b9604fe14eadba931b0ccf34843dab9"), InsecureSecretKeyAccess.get()))
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmSivKey).withRandomId().makePrimary())
            .build();
    Aead aead = keysetHandle.getPrimitive(Aead.class);

    // Encrypt an empty plaintext, and verify that it can be decrypted.
    byte[] ciphertext = aead.encrypt(new byte[] {1, 2, 3}, new byte[] {4, 5, 6});
    byte[] decrypted = aead.decrypt(ciphertext, new byte[] {4, 5, 6});
    assertThat(decrypted).isEqualTo(new byte[] {1, 2, 3});
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[] {4, 5}));
  }

  @Test
  public void testEncryptAndDecryptFailBeforeAndroid30() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeNotNull(apiLevel);
    Assume.assumeTrue(apiLevel < 30);

    // Use an AES GCM test vector from AesGcmJceTest.testWithAesGcmKey_noPrefix_works
    byte[] keyBytes = Hex.decode("5b9604fe14eadba931b0ccf34843dab9");
    AesGcmSivParameters parameters =
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build();
    com.google.crypto.tink.aead.AesGcmSivKey key =
        com.google.crypto.tink.aead.AesGcmSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.copyFrom(keyBytes, InsecureSecretKeyAccess.get()))
            .build();
    // Create an AEAD primitive for aesGcmSivKey.
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();
    Aead aead = keysetHandle.getPrimitive(Aead.class);

    assertThrows(GeneralSecurityException.class, () -> aead.encrypt(new byte[] {}, new byte[] {}));
    byte[] fixedCiphertext = Hex.decode("c3561ce7f48b8a6b9b8d5ef957d2e512368f7da837bcf2aeebe176e3");
    assertThrows(
        GeneralSecurityException.class, () -> aead.decrypt(fixedCiphertext, new byte[] {}));
  }

  // This test shows how ciphertexts created with older versions of Tink on older versions of
  // Android can still be decrypted with the current version of Tink.
  @Test
  public void testDecryptCiphertextCreatedOnOlderVersionOfAndroid() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    // A valid AES GCM SIV key.
    com.google.crypto.tink.aead.AesGcmSivKey aesGcmSivKey =
        com.google.crypto.tink.aead.AesGcmSivKey.builder()
            .setParameters(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("5b9604fe14eadba931b0ccf34843dab9"), InsecureSecretKeyAccess.get()))
            .build();

    // Valid ciphertext of an empty plaintext created with aesGcmSivKey.
    byte[] validCiphertext = Hex.decode("17871550708697c27881d04753337526f2bed57b7e2eac30ecde0202");

    // Ciphertext created with aesGcmSivKey on Android version 29 before
    // https://github.com/tink-crypto/tink-java/issues/18 was fixed.
    byte[] legacyCiphertext =
        Hex.decode("c3561ce7f48b8a6b9b8d5ef957d2e512368f7da837bcf2aeebe176e3");

    // Create an Aead instance that can decrypt in both AES GCM and AES GCM SIV.
    com.google.crypto.tink.aead.AesGcmKey legacyKey =
        com.google.crypto.tink.aead.AesGcmKey.builder()
            .setParameters(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .setKeyBytes(aesGcmSivKey.getKeyBytes())
            .build();
    KeysetHandle backwardsCompatibleKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(aesGcmSivKey).withRandomId().makePrimary())
            .addEntry(KeysetHandle.importKey(legacyKey).withRandomId())
            .build();
    Aead backwardsCompatibleAead = backwardsCompatibleKeysetHandle.getPrimitive(Aead.class);

    // Check that backwardsCompatibleAead can decrypt both valid and legacy ciphertexts.
    assertThat(backwardsCompatibleAead.decrypt(validCiphertext, new byte[] {})).isEmpty();
    assertThat(backwardsCompatibleAead.decrypt(legacyCiphertext, new byte[] {})).isEmpty();
  }
}
