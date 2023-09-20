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
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.AesSivKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
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
  }

  @Test
  public void basics() throws Exception {
    assertThat(new AesSivKeyManager().getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesSivKey");
    assertThat(new AesSivKeyManager().getVersion()).isEqualTo(0);
    assertThat(new AesSivKeyManager().keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () ->
            new AesSivKeyManager()
                .keyFactory()
                .validateKeyFormat(AesSivKeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKeyFormat_checkAllLengths() throws Exception {
    AesSivKeyManager manager = new AesSivKeyManager();
    for (int j = 0; j < 100; j++) {
      final int i = j;
      if (i == 64) {
        manager.keyFactory().validateKeyFormat(createAesSivKeyFormat(i));
      } else {
        assertThrows(
            GeneralSecurityException.class,
            () -> manager.keyFactory().validateKeyFormat(createAesSivKeyFormat(i)));
      }
    }
  }

  @Test
  public void validateKey_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> new AesSivKeyManager().validateKey(AesSivKey.getDefaultInstance()));
  }

  @Test
  public void validateKey_checkAllLengths() throws Exception {
    AesSivKeyManager manager = new AesSivKeyManager();
    for (int j = 0; j < 100; j++) {
      final int i = j;
      if (i == 64) {
        manager.validateKey(createAesSivKey(i));
      } else {
        assertThrows(GeneralSecurityException.class, () -> manager.validateKey(createAesSivKey(i)));
      }
    }
  }

  @Test
  public void validateKey_version() throws Exception {
    AesSivKeyManager manager = new AesSivKeyManager();
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(AesSivKey.newBuilder(createAesSivKey(64)).setVersion(1).build()));
  }

  @Test
  public void createKey_valid() throws Exception {
    AesSivKeyFormat format = createAesSivKeyFormat(64);
    AesSivKey key = new AesSivKeyManager().keyFactory().createKey(format);
    new AesSivKeyManager().validateKey(key);
  }

  @Test
  public void createKey_values() throws Exception {
    AesSivKeyFormat format = createAesSivKeyFormat(64);
    AesSivKey key = new AesSivKeyManager().keyFactory().createKey(format);
    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getKeyValue()).hasSize(format.getKeySize());
  }

  @Test
  public void createKey_multipleCallsCreateDifferentKeys() throws Exception {
    AesSivKeyFormat format = createAesSivKeyFormat(64);
    TreeSet<String> keys = new TreeSet<>();
    KeyTypeManager.KeyFactory<AesSivKeyFormat, AesSivKey> factory =
        new AesSivKeyManager().keyFactory();
    final int numKeys = 1000;
    for (int i = 0; i < numKeys; ++i) {
      keys.add(Hex.encode(factory.createKey(format).toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void testDeriveKey() throws Exception {
    final int keySize = 64;
    byte[] keyMaterial = Random.randBytes(100);
    AesSivKey key =
        new AesSivKeyManager()
            .keyFactory()
            .deriveKey(
                new AesSivKeyManager(),
                AesSivKeyFormat.newBuilder().setVersion(0).setKeySize(keySize).build(),
                new ByteArrayInputStream(keyMaterial));
    assertThat(key.getKeyValue()).hasSize(keySize);
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(keyMaterial[i]);
    }
  }

  @Test
  public void testDeriveKey_handlesDataFragmentationCorrectly() throws Exception {
    int keySize = 64;
    byte randomness = 4;
    InputStream fragmentedInputStream =
        new InputStream() {
          @Override
          public int read() {
            return 0;
          }

          @Override
          public int read(byte[] b, int off, int len) {
            b[off] = randomness;
            return 1;
          }
        };

    AesSivKey key =
        new AesSivKeyManager()
            .keyFactory()
            .deriveKey(
                new AesSivKeyManager(),
                AesSivKeyFormat.newBuilder().setVersion(0).setKeySize(keySize).build(),
                fragmentedInputStream);

    assertThat(key.getKeyValue()).hasSize(keySize);
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(randomness);
    }
  }

  @Test
  public void testDeriveKeyNotEnoughRandomness() throws Exception {
    final int keySize = 64;
    byte[] keyMaterial = Random.randBytes(10);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            new AesSivKeyManager()
                .keyFactory()
                .deriveKey(
                    new AesSivKeyManager(),
                    AesSivKeyFormat.newBuilder().setVersion(0).setKeySize(keySize).build(),
                    new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void testDeriveKeyWrongVersion() throws Exception {
    final int keySize = 64;
    byte[] keyMaterial = Random.randBytes(64);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            new AesSivKeyManager()
                .keyFactory()
                .deriveKey(
                    new AesSivKeyManager(),
                    AesSivKeyFormat.newBuilder().setVersion(1).setKeySize(keySize).build(),
                    new ByteArrayInputStream(keyMaterial)));
  }

  @Test
  public void testCiphertextSize() throws Exception {
    DeterministicAead daead =
        new AesSivKeyManager().getPrimitive(createAesSivKey(64), DeterministicAead.class);
    byte[] plaintext = "plaintext".getBytes("UTF-8");
    byte[] associatedData = "associatedData".getBytes("UTF-8");
    assertThat(daead.encryptDeterministically(plaintext, associatedData))
        .hasLength(plaintext.length + /* IV_SIZE= */ 16);
  }

  private AesSivKeyFormat createAesSivKeyFormat(int keySize) {
    return AesSivKeyFormat.newBuilder().setKeySize(keySize).build();
  }

  private AesSivKey createAesSivKey(int keySize) {
    return AesSivKey.newBuilder()
        .setKeyValue(ByteString.copyFrom(Random.randBytes(keySize)))
        .build();
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
}
