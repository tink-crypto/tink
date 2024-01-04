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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.prf.HkdfPrfKey;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.testing.StreamingTestUtil;
import com.google.crypto.tink.util.SecretBytes;
import java.io.ByteArrayInputStream;
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

/** Test for AesGcmHkdfStreamingKeyManager. */
@RunWith(Theories.class)
public class AesGcmHkdfStreamingKeyManagerTest {

  @Before
  public void register() throws Exception {
    StreamingAeadConfig.register();
    KeyDerivationConfig.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
                    StreamingAead.class))
        .isNotNull();
  }

  @Test
  public void getPrimitive_works() throws Exception {
    Parameters parameters = AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate().toParameters();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    StreamingAead streamingAead = handle.getPrimitive(StreamingAead.class);
    StreamingAead directAead =
        AesGcmHkdfStreaming.create(
            (com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey) handle.getAt(0).getKey());

    StreamingTestUtil.testEncryptDecryptDifferentInstances(
        streamingAead, directAead, 0, 2049, 1000);
  }

  @Test
  public void testSkip() throws Exception {
    KeysetHandle handle =
        KeysetHandle.generateNew(
            AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate().toParameters());
    StreamingAead streamingAead = handle.getPrimitive(StreamingAead.class);
    int offset = 0;
    int plaintextSize = 1 << 16;
    // Runs the test with different sizes for the chunks to skip.
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 1);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 64);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 300);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    Parameters parameters = AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate().toParameters();
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(parameters);
      com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey key =
          (com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(key.getInitialKeyMaterial().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void testAes128GcmHkdf4KBTemplate() throws Exception {
    KeyTemplate template = AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedAesGcmKeySizeBytes(16)
                .setCiphertextSegmentSizeBytes(4 * 1024)
                .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                .build());
  }

  @Test
  public void testAes256GcmHkdf4KBTemplate() throws Exception {
    KeyTemplate template = AesGcmHkdfStreamingKeyManager.aes256GcmHkdf4KBTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(32)
                .setDerivedAesGcmKeySizeBytes(32)
                .setCiphertextSegmentSizeBytes(4 * 1024)
                .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                .build());
  }

  @Test
  public void testAes128GcmHkdf1MBTemplate() throws Exception {
    KeyTemplate template = AesGcmHkdfStreamingKeyManager.aes128GcmHkdf1MBTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(16)
                .setDerivedAesGcmKeySizeBytes(16)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                .build());
  }

  @Test
  public void testAes256GcmHkdf1MBTemplate() throws Exception {
    KeyTemplate template = AesGcmHkdfStreamingKeyManager.aes256GcmHkdf1MBTemplate();
    assertThat(template.toParameters())
        .isEqualTo(
            AesGcmHkdfStreamingParameters.builder()
                .setKeySizeBytes(32)
                .setDerivedAesGcmKeySizeBytes(32)
                .setCiphertextSegmentSizeBytes(1024 * 1024)
                .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
                .build());
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "AES128_GCM_HKDF_4KB", "AES128_GCM_HKDF_1MB", "AES256_GCM_HKDF_4KB", "AES256_GCM_HKDF_1MB",
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
          47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
        };
    AesGcmHkdfStreamingParameters parameters =
        (AesGcmHkdfStreamingParameters) KeyTemplates.get(templateName).toParameters();
    com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKeyManager.createAesGcmHkdfStreamingKeyFromRandomness(
            parameters, new ByteArrayInputStream(keyMaterial), null, InsecureSecretKeyAccess.get());
    byte[] expectedKeyBytes = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey.create(
            parameters, SecretBytes.copyFrom(expectedKeyBytes, InsecureSecretKeyAccess.get()));
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testCreateKeyFromRandomness_slowInputStream_works() throws Exception {
    AesGcmHkdfStreamingParameters parameters =
        AesGcmHkdfStreamingParameters.builder()
            .setKeySizeBytes(16)
            .setDerivedAesGcmKeySizeBytes(16)
            .setCiphertextSegmentSizeBytes(1024 * 1024)
            .setHkdfHashType(AesGcmHkdfStreamingParameters.HashType.SHA256)
            .build();

    byte[] keyMaterial =
        new byte[] {
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
          25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
          47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
        };
    com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKeyManager.createAesGcmHkdfStreamingKeyFromRandomness(
            parameters, SlowInputStream.copyFrom(keyMaterial), null, InsecureSecretKeyAccess.get());
    byte[] expectedKeyBytes = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey.create(
            parameters, SecretBytes.copyFrom(expectedKeyBytes, InsecureSecretKeyAccess.get()));
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void deriveKeyset_isAsExpected() throws Exception {
    HkdfPrfKey prfKey =
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
            .setDerivedKeyParameters(PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB)
            .setPrfParameters(prfKey.getParameters())
            .build();

    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, /* idRequirement= */ null);
    KeysetHandle keyset =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keyDerivationKey).withFixedId(789789).makePrimary())
            .build();
    KeysetDeriver deriver = keyset.getPrimitive(KeysetDeriver.class);

    KeysetHandle derivedKeyset = deriver.deriveKeyset(Hex.decode("000102"));

    assertThat(derivedKeyset.size()).isEqualTo(1);
    // The only thing which we need to test is equalsKey(), but we first test other things to make
    // test failures have nicer messages.
    assertThat(derivedKeyset.getAt(0).getKey().getParameters())
        .isEqualTo(derivationParameters.getDerivedKeyParameters());
    assertTrue(
        derivedKeyset
            .getAt(0)
            .getKey()
            .equalsKey(
                com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKey.create(
                    PredefinedStreamingAeadParameters.AES256_GCM_HKDF_1MB,
                    SecretBytes.copyFrom(
                        Hex.decode(
                            "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad90eeb24"),
                        InsecureSecretKeyAccess.get()))));
  }

  @Test
  public void serializeAndParse_works() throws Exception {
    Parameters parameters = AesGcmHkdfStreamingKeyManager.aes128GcmHkdf4KBTemplate().toParameters();
    KeysetHandle handle = KeysetHandle.generateNew(parameters);
    byte[] serializedHandle =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsedHandle =
        TinkProtoKeysetFormat.parseKeyset(serializedHandle, InsecureSecretKeyAccess.get());
    assertThat(parsedHandle.equalsKeyset(handle)).isTrue();
  }
}
