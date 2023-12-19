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

package com.google.crypto.tink.keyderivation.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.prf.HkdfPrfKeyManager;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.prf.PrfKey;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKey;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.PrfBasedDeriverKey;
import com.google.crypto.tink.proto.PrfBasedDeriverKeyFormat;
import com.google.crypto.tink.proto.PrfBasedDeriverParams;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for PrfBasedDeriverKeyManager. */
@RunWith(JUnit4.class)
public class PrfBasedDeriverKeyManagerTest {
  private final PrfBasedDeriverKeyManager manager = new PrfBasedDeriverKeyManager();
  private final KeyTypeManager.KeyFactory<PrfBasedDeriverKeyFormat, PrfBasedDeriverKey> factory =
      manager.keyFactory();

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
    KeyDerivationConfig.register();
    PrfConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKey_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(PrfBasedDeriverKey.getDefaultInstance()));
  }

  @Test
  public void validateKey_valid() throws Exception {
    HkdfPrfKey prfKey =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(10)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKey key =
        PrfBasedDeriverKey.newBuilder()
            .setPrfKey(
                TestUtil.createKeyData(
                    prfKey, HkdfPrfKeyManager.staticKeyType(), KeyMaterialType.SYMMETRIC))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();
    manager.validateKey(key);
  }

  @Test
  public void validateKey_wrongVersion_throws() throws Exception {
    HkdfPrfKey prfKey =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(10)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKey key =
        PrfBasedDeriverKey.newBuilder()
            .setPrfKey(
                TestUtil.createKeyData(
                    prfKey, HkdfPrfKeyManager.staticKeyType(), KeyMaterialType.SYMMETRIC))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .setVersion(1)
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKeyFormat_empty() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> factory.validateKeyFormat(PrfBasedDeriverKeyFormat.getDefaultInstance()));
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();
    factory.validateKeyFormat(keyFormat);
  }

  @Test
  public void createKey_checkValues() throws Exception {
    HkdfPrfKeyManager.register(true);
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();
    PrfBasedDeriverKey key = factory.createKey(keyFormat);

    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getPrfKey().getTypeUrl()).isEqualTo(HkdfPrfKeyManager.staticKeyType());
    assertThat(key.getPrfKey().getKeyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
    HkdfPrfKey hkdfPrfKey =
        HkdfPrfKey.parseFrom(key.getPrfKey().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(hkdfPrfKey.getKeyValue()).hasSize(32);
    assertThat(key.getParams()).isEqualTo(keyFormat.getParams());
  }

  @Test
  public void createKey_invalidPrfKey_throws() throws Exception {
    HkdfPrfKeyManager.register(true);
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.UNKNOWN_HASH))
            .build();
    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(AeadKeyTemplates.AES256_GCM))
            .build();
    assertThrows(GeneralSecurityException.class, () -> factory.createKey(keyFormat));
  }

  @Test
  public void createKey_invalidDerivedKeyTemplate_throws() throws Exception {
    HkdfPrfKeyManager.register(true);
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setTypeUrl(HkdfPrfKeyManager.staticKeyType())
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(
                PrfBasedDeriverParams.newBuilder()
                    .setDerivedKeyTemplate(
                        KeyTemplate.newBuilder().setTypeUrl("nonexistenttypeurl").build()))
            .build();
    assertThrows(GeneralSecurityException.class, () -> factory.createKey(keyFormat));
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getUntypedKeyManager("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"))
        .isNotNull();
  }

  @Test
  public void createKey_works() throws Exception {
    PrfBasedKeyDerivationParameters params =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setDerivedKeyParameters(XChaCha20Poly1305Parameters.create())
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    PrfBasedKeyDerivationKey key = (PrfBasedKeyDerivationKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_otherParams_works() throws Exception {
    // We repeat the above test just to check that no part of Tink somehow inlines  default
    // parameters for this somewhere and we ignore some inputs.
    PrfBasedKeyDerivationParameters params =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA512)
                    .build())
            .setDerivedKeyParameters(
                XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK))
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    PrfBasedKeyDerivationKey key = (PrfBasedKeyDerivationKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_differentKeyValues_alwaysDifferent() throws Exception {
    PrfBasedKeyDerivationParameters params =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setDerivedKeyParameters(XChaCha20Poly1305Parameters.create())
            .build();

    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      PrfBasedKeyDerivationKey key = (PrfBasedKeyDerivationKey) handle.getAt(0).getKey();
      com.google.crypto.tink.prf.HkdfPrfKey prfKey =
          (com.google.crypto.tink.prf.HkdfPrfKey) key.getPrfKey();
      keys.add(Hex.encode(prfKey.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys.size()).isEqualTo(numKeys);
  }

  @Test
  public void createPrimitiveAndUseIt_works() throws Exception {
    // Test vector from PrfBasedDeriverSecondTest. (FIXED_PRF_KEY)
    PrfKey prfKey =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
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
            .setDerivedKeyParameters(PredefinedAeadParameters.AES128_GCM)
            .setPrfParameters(prfKey.getParameters())
            .build();
    PrfBasedKeyDerivationKey keyDerivationKey =
        PrfBasedKeyDerivationKey.create(derivationParameters, prfKey, 123);

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(keyDerivationKey).makePrimary().withFixedId(123))
            .build();
    KeysetDeriver deriver = handle.getPrimitive(KeysetDeriver.class);

    Key expectedKey =
        AesGcmKey.builder()
            .setParameters(PredefinedAeadParameters.AES128_GCM)
            .setIdRequirement(123)
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("1b73bdf5293cc533d635f263e35913ec"), InsecureSecretKeyAccess.get()))
            .build();
    KeysetHandle derivedKeysetHandle = deriver.deriveKeyset(new byte[0]);
    assertThat(derivedKeysetHandle.getAt(0).getKey().getParameters())
        .isEqualTo(PredefinedAeadParameters.AES128_GCM);
    assertThat(derivedKeysetHandle.getAt(0).getKey().equalsKey(expectedKey)).isTrue();
  }

  @Test
  public void checkSerializationRegistered() throws Exception {
    PrfBasedKeyDerivationParameters params =
        PrfBasedKeyDerivationParameters.builder()
            .setPrfParameters(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build())
            .setDerivedKeyParameters(XChaCha20Poly1305Parameters.create())
            .build();

    KeysetHandle handle = KeysetHandle.generateNew(params);

    byte[] serialized =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serialized, InsecureSecretKeyAccess.get());

    assertTrue(parsed.equalsKeyset(handle));
  }
}
