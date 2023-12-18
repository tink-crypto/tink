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
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.PrfKey;
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
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
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
    KeyDerivationConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey", Aead.class))
        .isNotNull();
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
  public void getPrimtive_encryptDecryptTink_worksAsDirectlyCreated() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setTagSizeBytes(17)
            .setIvSizeBytes(14)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.aead.AesCtrHmacAeadKey key =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .setParameters(parameters)
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = keysetHandle.getPrimitive(Aead.class);
    Aead directAead = EncryptThenAuthenticate.create(key);

    assertThat(directAead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
    assertThat(aead.decrypt(directAead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }

  @Test
  public void getPrimitive_encryptDecryptCrunchy_works() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(32)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setTagSizeBytes(18)
            .setIvSizeBytes(13)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    com.google.crypto.tink.aead.AesCtrHmacAeadKey key =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(16))
            .setHmacKeyBytes(SecretBytes.randomBytes(32))
            .setParameters(parameters)
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    Aead aead = keysetHandle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(aead.encrypt(plaintext, aad), aad)).isEqualTo(plaintext);
  }

  @Test
  public void getPrimitive_bitFlipCiphertext_throws() throws Exception {
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA512)
            .setTagSizeBytes(16)
            .setIvSizeBytes(12)
            .setVariant(AesCtrHmacAeadParameters.Variant.CRUNCHY)
            .build();
    com.google.crypto.tink.aead.AesCtrHmacAeadKey key =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setHmacKeyBytes(SecretBytes.randomBytes(16))
            .setParameters(parameters)
            .setIdRequirement(42)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = Random.randBytes(1001);
    byte[] aad = Random.randBytes(13);

    Aead aead = keysetHandle.getPrimitive(Aead.class);
    byte[] ciphertext = aead.encrypt(plaintext, aad);

    for (int i = 0; i < ciphertext.length; i++) {
      for (int j = 0; j < 8; j++) {
        byte[] c1 = Arrays.copyOf(ciphertext, ciphertext.length);
        c1[i] = (byte) (c1[i] ^ (1 << j));
        assertThrows(GeneralSecurityException.class, () -> aead.decrypt(c1, aad));
      }
    }
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
  public void testKeyTemplatesWork() throws Exception {
    Parameters p = AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
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

  @Test
  public void callingCreateTwiceGivesDifferentKeys() throws Exception {
    Parameters p = AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template().toParameters();
    Key key = KeysetHandle.generateNew(p).getAt(0).getKey();
    for (int i = 0; i < 1000; ++i) {
      assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().equalsKey(key)).isFalse();
    }
  }

  @Theory
  public void testCreateKeyFromRandomness(@FromDataPoints("templateNames") String templateName)
      throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
          47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
        };
    AesCtrHmacAeadParameters parameters =
        (AesCtrHmacAeadParameters) KeyTemplates.get(templateName).toParameters();
    com.google.crypto.tink.aead.AesCtrHmacAeadKey key =
        AesCtrHmacAeadKeyManager.createAesCtrHmacAeadKeyFromRandomness(
            parameters,
            new ByteArrayInputStream(keyMaterial),
            parameters.hasIdRequirement() ? 123 : null,
            InsecureSecretKeyAccess.get());
    byte[] expectedAesKey = Arrays.copyOf(keyMaterial, parameters.getAesKeySizeBytes());
    byte[] expectedHmacKey =
        Arrays.copyOfRange(
            keyMaterial,
            parameters.getAesKeySizeBytes(),
            parameters.getAesKeySizeBytes() + parameters.getHmacKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
            .setAesKeyBytes(SecretBytes.copyFrom(expectedAesKey, InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(SecretBytes.copyFrom(expectedHmacKey, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
          47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
        };
    AesCtrHmacAeadParameters parameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(32)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.aead.AesCtrHmacAeadKey key =
        AesCtrHmacAeadKeyManager.createAesCtrHmacAeadKeyFromRandomness(
            parameters,
            SlowInputStream.copyFrom(keyMaterial),
            12347,
            InsecureSecretKeyAccess.get());
    byte[] expectedAesKey = Arrays.copyOf(keyMaterial, parameters.getAesKeySizeBytes());
    byte[] expectedHmacKey =
        Arrays.copyOfRange(
            keyMaterial,
            parameters.getAesKeySizeBytes(),
            parameters.getAesKeySizeBytes() + parameters.getHmacKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(parameters)
            .setIdRequirement(12347)
            .setAesKeyBytes(SecretBytes.copyFrom(expectedAesKey, InsecureSecretKeyAccess.get()))
            .setHmacKeyBytes(SecretBytes.copyFrom(expectedHmacKey, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  private static PrfBasedKeyDerivationKey createDerivationKey(Parameters derivedParameters, int id)
      throws Exception {
    PrfKey prfKey =
        HkdfPrfKey.builder()
            .setParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("0102030405060708091011121314151617181920212123242526272829303132"),
                    InsecureSecretKeyAccess.get()))
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(derivedParameters)
            .setPrfParameters(prfKey.getParameters())
            .build();
    return PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ id);
  }

  private static final SecretBytes secretBytesFromHex(String hex) {
    return SecretBytes.copyFrom(Hex.decode(hex), InsecureSecretKeyAccess.get());
  }

  @Test
  public void testDeriveKey_predefinedKey_works() throws Exception {
    // Same test vector as in PrfBasedKeyDeriverTest
    KeysetDeriver deriver =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        createDerivationKey(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256, 24680))
                    .makePrimary())
            .build()
            .getPrimitive(KeysetDeriver.class);
    KeysetHandle derivedKeyset = deriver.deriveKeyset(Hex.decode("000102"));
    assertThat(derivedKeyset.size()).isEqualTo(1);
    assertThat(derivedKeyset.getAt(0).getKey().getParameters())
        .isEqualTo(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256);
    Key expectedKey =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(PredefinedAeadParameters.AES128_CTR_HMAC_SHA256)
            .setIdRequirement(24680)
            .setAesKeyBytes(secretBytesFromHex("94e397d674deda6e965295698491a3fe"))
            .setHmacKeyBytes(
                secretBytesFromHex(
                    "b69838a35f1d48143f3c4cbad90eeb249c8ddea6d09adc5f89a9a190122b095d"))
            .build();

    KeysetHandle expectedKeyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(expectedKey).makePrimary())
            .build();
    assertTrue(derivedKeyset.equalsKeyset(expectedKeyset));
  }

  @Test
  public void testDeriveKey_24byteAes_throws() throws Exception {
    KeysetHandle derivationHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        createDerivationKey(
                            AesCtrHmacAeadParameters.builder()
                                .setAesKeySizeBytes(24)
                                .setHmacKeySizeBytes(32)
                                .setTagSizeBytes(16)
                                .setIvSizeBytes(16)
                                .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                                .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                                .build(),
                            24680))
                    .makePrimary())
            .build();
    // TODO(tholenst): This should throw.
    Object unused =
        derivationHandle.getPrimitive(KeysetDeriver.class).deriveKeyset(Hex.decode("000102"));
  }

  @Test
  public void testNewKey_validationHappens_throws() throws Exception {
    AesCtrHmacAeadParameters rejectedParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(24)
            .setHmacKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(32)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.generateNew(rejectedParameters));
  }

  @Test
  public void testGetPrimitive_validationHappens_throws() throws Exception {
    AesCtrHmacAeadParameters rejectedParameters =
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(24)
            .setHmacKeySizeBytes(32)
            .setIvSizeBytes(16)
            .setTagSizeBytes(32)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.aead.AesCtrHmacAeadKey rejectedKey =
        com.google.crypto.tink.aead.AesCtrHmacAeadKey.builder()
            .setParameters(rejectedParameters)
            .setIdRequirement(123456)
            .setAesKeyBytes(SecretBytes.randomBytes(rejectedParameters.getAesKeySizeBytes()))
            .setHmacKeyBytes(SecretBytes.randomBytes(rejectedParameters.getHmacKeySizeBytes()))
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            KeysetHandle.newBuilder()
                .addEntry(KeysetHandle.importKey(rejectedKey).makePrimary())
                .build()
                .getPrimitive(Aead.class));
  }
}
