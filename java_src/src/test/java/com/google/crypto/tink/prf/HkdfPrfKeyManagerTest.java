// Copyright 2020 Google LLC
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
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
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

/** Tests for HkdfPrfKeyManager. */
@RunWith(Theories.class)
public class HkdfPrfKeyManagerTest {
  @Before
  public void register() throws Exception {
    PrfConfig.register();
    KeyDerivationConfig.register();
    AeadConfig.register();
  }

  @Test
  public void testHkdfSha256Template() throws Exception {
    KeyTemplate kt = HkdfPrfKeyManager.hkdfSha256Template();
    assertThat(kt.toParameters())
        .isEqualTo(
            HkdfPrfParameters.builder()
                .setKeySizeBytes(32)
                .setHashType(HkdfPrfParameters.HashType.SHA256)
                .setSalt(Bytes.copyFrom(new byte[] {}))
                .build());
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    Parameters p = HkdfPrfKeyManager.hkdfSha256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "HKDF_SHA256",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void register_registersPrfPrimitiveConstructor() throws Exception {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setKeySizeBytes(32)
            .setSalt(Bytes.copyFrom(Random.randBytes(5)))
            .build();
    com.google.crypto.tink.prf.HkdfPrfKey hkdfPrfKey =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(SecretBytes.copyFrom(Random.randBytes(32), InsecureSecretKeyAccess.get()))
            .build();

    Prf prf = MutablePrimitiveRegistry.globalInstance().getPrimitive(hkdfPrfKey, Prf.class);

    assertThat(prf).isNotNull();
  }

  @Test
  public void register_registersStreamingPrfPrimitiveConstructor() throws Exception {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setKeySizeBytes(32)
            .setSalt(Bytes.copyFrom(Random.randBytes(5)))
            .build();
    com.google.crypto.tink.prf.HkdfPrfKey hkdfPrfKey =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(SecretBytes.copyFrom(Random.randBytes(32), InsecureSecretKeyAccess.get()))
            .build();

    StreamingPrf streamingPrf =
        MutablePrimitiveRegistry.globalInstance().getPrimitive(hkdfPrfKey, StreamingPrf.class);

    assertThat(streamingPrf).isNotNull();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.HkdfPrfKey", Prf.class))
        .isNotNull();
  }

  @Test
  public void createKey_works() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    com.google.crypto.tink.prf.HkdfPrfKey key =
        (com.google.crypto.tink.prf.HkdfPrfKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_otherParams_works() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    com.google.crypto.tink.prf.HkdfPrfKey key =
        (com.google.crypto.tink.prf.HkdfPrfKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_differentKeyValues_alwaysDifferent() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();

    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      com.google.crypto.tink.prf.HkdfPrfKey key =
          (com.google.crypto.tink.prf.HkdfPrfKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createPrimitiveAndUseIt_works() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    PrfSet prfSet = handle.getPrimitive(PrfSet.class);
    Prf directPrf =
        PrfImpl.wrap(
            HkdfStreamingPrf.create(
                (com.google.crypto.tink.prf.HkdfPrfKey) handle.getAt(0).getKey()));
    assertThat(prfSet.computePrimary(new byte[0], 16))
        .isEqualTo(directPrf.compute(new byte[0], 16));
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Theory
  public void createKeyWithRejectedParameters_throws(
      @FromDataPoints("KeyManager rejected") HkdfPrfParameters params) throws Exception {
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(params));
  }

  @Theory
  public void createPrimitiveWithRejectedParameters_throws(
      @FromDataPoints("KeyManager rejected") HkdfPrfParameters params) throws Exception {
    com.google.crypto.tink.prf.HkdfPrfKey key =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
            .setParameters(params)
            .setKeyBytes(SecretBytes.randomBytes(params.getKeySizeBytes()))
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1).makePrimary())
            .build();
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(PrfSet.class));
  }

  /** We allow serialization and deserialization with parameters which are otherwise rejected */
  @Theory
  public void serializeDeserializeKeysetsWithRejectedParams_works(
      @FromDataPoints("KeyManager rejected") HkdfPrfParameters params) throws Exception {
    com.google.crypto.tink.prf.HkdfPrfKey key =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
            .setParameters(params)
            .setKeyBytes(SecretBytes.randomBytes(params.getKeySizeBytes()))
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1).makePrimary())
            .build();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Theory
  public void deriveAesGcmKey_withInvalidPrfParameters_throws(
      @FromDataPoints("KeyManager rejected") HkdfPrfParameters params) throws Exception {
    PrfKey prfKeyForDeriver =
        HkdfPrfKey.builder()
            .setParameters(params)
            .setKeyBytes(SecretBytes.randomBytes(params.getKeySizeBytes()))
            .build();
    PrfBasedKeyDerivationParameters derivationParameters =
        PrfBasedKeyDerivationParameters.builder()
            .setDerivedKeyParameters(PredefinedAeadParameters.AES128_GCM)
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

  private static HkdfPrfParameters[] createRejectedParameters() {
    return exceptionIsBug(
        () ->
            new HkdfPrfParameters[] {
              // Key Size 16 is rejected
              HkdfPrfParameters.builder()
                  .setHashType(HkdfPrfParameters.HashType.SHA512)
                  .setKeySizeBytes(16)
                  .build(),
              // Only SHA256 and SHA512 are accepted
              HkdfPrfParameters.builder()
                  .setHashType(HkdfPrfParameters.HashType.SHA1)
                  .setKeySizeBytes(32)
                  .build(),
              HkdfPrfParameters.builder()
                  .setHashType(HkdfPrfParameters.HashType.SHA224)
                  .setKeySizeBytes(32)
                  .build(),
              HkdfPrfParameters.builder()
                  .setHashType(HkdfPrfParameters.HashType.SHA384)
                  .setKeySizeBytes(32)
                  .build()
            });
  }

  @DataPoints("KeyManager rejected")
  public static final HkdfPrfParameters[] RECJECTED_PARAMETERS = createRejectedParameters();
}
