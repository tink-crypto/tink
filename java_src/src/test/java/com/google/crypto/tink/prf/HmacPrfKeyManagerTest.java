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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.SlowInputStream;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.PrfHmacJce;
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

/** Unit tests for {@link HmacPrfKeyManager}. */
@RunWith(Theories.class)
public class HmacPrfKeyManagerTest {
  @Before
  public void register() throws Exception {
    KeyDerivationConfig.register();
    PrfConfig.register();
  }

  @Test
  public void testHmacSha256Template() throws Exception {
    KeyTemplate template = HmacPrfKeyManager.hmacSha256Template();
    assertThat(template.toParameters())
        .isEqualTo(
            HmacPrfParameters.builder()
                .setKeySizeBytes(32)
                .setHashType(HmacPrfParameters.HashType.SHA256)
                .build());
  }

  @Test
  public void testHmacSha512Template() throws Exception {
    KeyTemplate template = HmacPrfKeyManager.hmacSha512Template();
    assertThat(template.toParameters())
        .isEqualTo(
            HmacPrfParameters.builder()
                .setKeySizeBytes(64)
                .setHashType(HmacPrfParameters.HashType.SHA512)
                .build());
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    Parameters p = HmacPrfKeyManager.hmacSha256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);

    p = HmacPrfKeyManager.hmacSha256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES = new String[] {"HMAC_SHA256_PRF", "HMAC_SHA512_PRF"};

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void registersPrfPrimitiveConstructor() throws Exception {
    Prf prf =
        MutablePrimitiveRegistry.globalInstance()
            .getPrimitive(
                com.google.crypto.tink.prf.HmacPrfKey.builder()
                    .setParameters(
                        HmacPrfParameters.builder()
                            .setHashType(HmacPrfParameters.HashType.SHA256)
                            .setKeySizeBytes(32)
                            .build())
                    .setKeyBytes(SecretBytes.randomBytes(32))
                    .build(),
                Prf.class);

    assertThat(prf).isInstanceOf(PrfHmacJce.class);
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
    HmacPrfParameters parameters =
        (HmacPrfParameters) KeyTemplates.get(templateName).toParameters();
    com.google.crypto.tink.prf.HmacPrfKey key =
        HmacPrfKeyManager.createHmacKeyFromRandomness(
            parameters, new ByteArrayInputStream(keyMaterial), null, InsecureSecretKeyAccess.get());
    byte[] expectedKeyBytes = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.prf.HmacPrfKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.copyFrom(expectedKeyBytes, InsecureSecretKeyAccess.get()))
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
    HmacPrfParameters parameters =
        HmacPrfParameters.builder()
            .setKeySizeBytes(64)
            .setHashType(HmacPrfParameters.HashType.SHA512)
            .build();
    com.google.crypto.tink.prf.HmacPrfKey key =
        HmacPrfKeyManager.createHmacKeyFromRandomness(
            parameters, SlowInputStream.copyFrom(keyMaterial), null, InsecureSecretKeyAccess.get());
    byte[] expectedKeyBytes = Arrays.copyOf(keyMaterial, parameters.getKeySizeBytes());
    Key expectedKey =
        com.google.crypto.tink.prf.HmacPrfKey.builder()
            .setParameters(parameters)
            .setKeyBytes(SecretBytes.copyFrom(expectedKeyBytes, InsecureSecretKeyAccess.get()))
            .build();
    assertTrue(key.equalsKey(expectedKey));
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.HmacPrfKey", Prf.class))
        .isNotNull();
  }

  @Test
  public void createKey_works() throws Exception {
    HmacPrfParameters params =
        HmacPrfParameters.builder()
            .setHashType(HmacPrfParameters.HashType.SHA256)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    com.google.crypto.tink.prf.HmacPrfKey key =
        (com.google.crypto.tink.prf.HmacPrfKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_otherParams_works() throws Exception {
    HmacPrfParameters params =
        HmacPrfParameters.builder()
            .setHashType(HmacPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    com.google.crypto.tink.prf.HmacPrfKey key =
        (com.google.crypto.tink.prf.HmacPrfKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_differentKeyValues_alwaysDifferent() throws Exception {
    HmacPrfParameters params =
        HmacPrfParameters.builder()
            .setHashType(HmacPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();

    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      com.google.crypto.tink.prf.HmacPrfKey key =
          (com.google.crypto.tink.prf.HmacPrfKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createPrimitiveAndUseIt_works() throws Exception {
    HmacPrfParameters params =
        HmacPrfParameters.builder()
            .setHashType(HmacPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    PrfSet prfSet = handle.getPrimitive(PrfSet.class);
    Prf directPrf =
        PrfHmacJce.create((com.google.crypto.tink.prf.HmacPrfKey) handle.getAt(0).getKey());
    assertThat(prfSet.computePrimary(new byte[0], 16))
        .isEqualTo(directPrf.compute(new byte[0], 16));
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    HmacPrfParameters params =
        HmacPrfParameters.builder()
            .setHashType(HmacPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Test
  public void deriveHmacPrfKey_works() throws Exception {
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
            .setDerivedKeyParameters(PredefinedPrfParameters.HMAC_SHA256_PRF)
            .setPrfParameters(prfKeyForDeriver.getParameters())
            .build();
    PrfBasedKeyDerivationKey key =
        PrfBasedKeyDerivationKey.create(
            derivationParameters, prfKeyForDeriver, /* idRequirement= */ null);

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
                    com.google.crypto.tink.prf.HmacPrfKey.builder()
                        .setParameters(PredefinedPrfParameters.HMAC_SHA256_PRF)
                        .setKeyBytes(
                            SecretBytes.copyFrom(
                                Hex.decode(
                                    "94e397d674deda6e965295698491a3feb69838a35f1d48143f3c4cbad9"
                                        + "0eeb24"),
                                InsecureSecretKeyAccess.get()))
                        .build()))
        .isTrue();
  }
}
