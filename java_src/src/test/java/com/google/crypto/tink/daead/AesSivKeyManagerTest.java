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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.PrfKey;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Hex;
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

/** Test for AesSivKeyManager. */
@RunWith(Theories.class)
public class AesSivKeyManagerTest {

  @Before
  public void register() throws Exception {
    DeterministicAeadConfig.register();
    KeyDerivationConfig.register();
  }

  @Test
  public void testAes256SivTemplate() throws Exception {
    KeyTemplate template = AesSivKeyManager.aes256SivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesSivParameters.builder()
                .setKeySizeBytes(64)
                .setVariant(AesSivParameters.Variant.TINK)
                .build());
  }

  @Test
  public void testRawAes256SivTemplate() throws Exception {
    KeyTemplate template = AesSivKeyManager.rawAes256SivTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesSivParameters.builder()
                .setKeySizeBytes(64)
                .setVariant(AesSivParameters.Variant.NO_PREFIX)
                .build());
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "AES256_SIV", "AES256_SIV_RAW",
      };

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
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
          47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 66, 67, 68, 69,
        };
    AesSivParameters parameters = (AesSivParameters) KeyTemplates.get(templateName).toParameters();
    com.google.crypto.tink.daead.AesSivKey key =
        AesSivKeyManager.createAesSivKeyFromRandomness(
            parameters,
            new ByteArrayInputStream(keyMaterial),
            parameters.hasIdRequirement() ? 123 : null,
            InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.daead.AesSivKey.builder()
            .setParameters(parameters)
            .setIdRequirement(parameters.hasIdRequirement() ? 123 : null)
            .setKeyBytes(SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
          47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 66, 67, 68, 69,
        };
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.daead.AesSivKey key =
        AesSivKeyManager.createAesSivKeyFromRandomness(
            parameters,
            SlowInputStream.copyFrom(keyMaterial),
            88123,
            InsecureSecretKeyAccess.get());
    byte[] truncatedKeyMaterial = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.daead.AesSivKey.builder()
            .setParameters(parameters)
            .setIdRequirement(88123)
            .setKeyBytes(SecretBytes.copyFrom(truncatedKeyMaterial, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void getPrimitiveFromKeysetHandle() throws Exception {
    AesSivParameters parameters =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.daead.AesSivKey key =
        com.google.crypto.tink.daead.AesSivKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.randomBytes(64))
            .setIdRequirement(31)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] aad = "aad".getBytes(UTF_8);

    DeterministicAead daead = keysetHandle.getPrimitive(DeterministicAead.class);
    DeterministicAead directDaead = AesSiv.create(key);

    Object unused =
        directDaead.decryptDeterministically(daead.encryptDeterministically(plaintext, aad), aad);
    unused =
        daead.decryptDeterministically(directDaead.encryptDeterministically(plaintext, aad), aad);
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.AesSivKey", DeterministicAead.class))
        .isNotNull();
  }

  @Test
  public void createKey_works() throws Exception {
    AesSivParameters params =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    com.google.crypto.tink.daead.AesSivKey key =
        (com.google.crypto.tink.daead.AesSivKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_differentKeyValues_alwaysDifferent() throws Exception {
    AesSivParameters params =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();

    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      com.google.crypto.tink.daead.AesSivKey key =
          (com.google.crypto.tink.daead.AesSivKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createPrimitiveAndUseIt_works() throws Exception {
    AesSivParameters params =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    DeterministicAead daead = handle.getPrimitive(DeterministicAead.class);
    DeterministicAead directDaead =
        AesSiv.create((com.google.crypto.tink.daead.AesSivKey) handle.getAt(0).getKey());
    byte[] ciphertext = daead.encryptDeterministically(new byte[] {1, 2, 3}, new byte[0]);
    assertThat(directDaead.decryptDeterministically(ciphertext, new byte[0]))
        .isEqualTo(new byte[] {1, 2, 3});
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    AesSivParameters params =
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Test
  public void createKeyWith32Bytes_throws() throws Exception {
    AesSivParameters params =
        AesSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(params));
  }

  @Test
  public void createPrimitiveWith32Bytes_throws() throws Exception {
    AesSivParameters params =
        AesSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.daead.AesSivKey key =
        com.google.crypto.tink.daead.AesSivKey.builder()
            .setParameters(params)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(3133)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(3133).makePrimary())
            .build();
    assertThrows(
        GeneralSecurityException.class, () -> handle.getPrimitive(DeterministicAead.class));
  }

  @Test
  public void serializeDeserializeKeysetsWith16Bytes_works() throws Exception {
    AesSivParameters params =
        AesSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesSivParameters.Variant.TINK)
            .build();
    com.google.crypto.tink.daead.AesSivKey key =
        com.google.crypto.tink.daead.AesSivKey.builder()
            .setParameters(params)
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(3133)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(3133).makePrimary())
            .build();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  private static final SecretBytes secretBytesFromHex(String hex) {
    return SecretBytes.copyFrom(Hex.decode(hex), InsecureSecretKeyAccess.get());
  }

  @Test
  public void deriveAesSivKey_works() throws Exception {
    PrfKey prfKeyForDeriver =
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
            .setDerivedKeyParameters(PredefinedDeterministicAeadParameters.AES256_SIV)
            .setPrfParameters(prfKeyForDeriver.getParameters())
            .build();
    PrfBasedKeyDerivationKey key =
        PrfBasedKeyDerivationKey.create(
            derivationParameters, prfKeyForDeriver, /* idRequirement= */ 112233);

    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(112233).makePrimary())
            .build();
    KeysetDeriver deriver = keyset.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedKeyset = deriver.deriveKeyset(Hex.decode("000102"));

    assertThat(derivedKeyset.size()).isEqualTo(1);
    assertThat(
            derivedKeyset
                .getAt(0)
                .getKey()
                .equalsKey(
                    com.google.crypto.tink.daead.AesSivKey.builder()
                        .setParameters(PredefinedDeterministicAeadParameters.AES256_SIV)
                        .setIdRequirement(112233)
                        .setKeyBytes(
                            secretBytesFromHex(
                                "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"
                                    + "9c8ddea6d09adc5f89a9a190122b095d34e166df93b36f417d63baac78"
                                    + "115ac3"))
                        .build()))
        .isTrue();
  }

  @Test
  public void deriveAesSivKey_with32bytes_throws() throws Exception {
    PrfKey prfKeyForDeriver =
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
            .setDerivedKeyParameters(
                AesSivParameters.builder()
                    .setKeySizeBytes(32)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build())
            .setPrfParameters(prfKeyForDeriver.getParameters())
            .build();
    PrfBasedKeyDerivationKey key =
        PrfBasedKeyDerivationKey.create(
            derivationParameters, prfKeyForDeriver, /* idRequirement= */ 112233);

    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(112233).makePrimary())
            .build();
    assertThrows(GeneralSecurityException.class, () -> keyset.getPrimitive(KeysetDeriver.class));
  }
}
