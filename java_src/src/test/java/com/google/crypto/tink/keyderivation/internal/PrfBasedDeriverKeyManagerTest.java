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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.keyderivation.KeyDerivationConfig;
import com.google.crypto.tink.keyderivation.KeysetDeriver;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.prf.HkdfPrfParameters;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.prf.PrfKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKey;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.PrfBasedDeriverKey;
import com.google.crypto.tink.proto.PrfBasedDeriverKeyFormat;
import com.google.crypto.tink.proto.PrfBasedDeriverParams;
import com.google.crypto.tink.subtle.Hex;
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
  private static KeyManager<?> manager;

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
    KeyDerivationConfig.register();
    PrfConfig.register();

    manager =
        KeyManagerRegistry.globalInstance()
            .getUntypedKeyManager("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  }

  /** We test newKey directly because PrfBasedDeriverKeyManager has its own implementation. */
  @Test
  @SuppressWarnings("deprecation") // This is a test for the deprecated function
  public void newKey_works() throws Exception {
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setHash(HashType.SHA256)
                    .setSalt(ByteString.copyFrom(new byte[] {1, 2, 3})))
            .build();
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(16).build();
    KeyTemplate derivedKeyTemplate =
        KeyTemplate.newBuilder()
            .setValue(format.toByteString())
            .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setOutputPrefixType(OutputPrefixType.RAW)
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.HkdfPrfKey")
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(PrfBasedDeriverParams.newBuilder().setDerivedKeyTemplate(derivedKeyTemplate))
            .build();

    PrfBasedDeriverKey prfBasedDeriverKey =
        (PrfBasedDeriverKey) manager.newKey(keyFormat.toByteString());

    assertThat(prfBasedDeriverKey.getParams().getDerivedKeyTemplate())
        .isEqualTo(derivedKeyTemplate);
    assertThat(prfBasedDeriverKey.getPrfKey().getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.HkdfPrfKey");
    assertThat(prfBasedDeriverKey.getPrfKey().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.SYMMETRIC);
    HkdfPrfKey hkdfPrfKey =
        HkdfPrfKey.parseFrom(
            prfBasedDeriverKey.getPrfKey().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(hkdfPrfKey.getParams()).isEqualTo(prfKeyFormat.getParams());
    assertThat(hkdfPrfKey.getKeyValue()).hasSize(prfKeyFormat.getKeySize());
  }

  /** We test newKey directly because PrfBasedDeriverKeyManager has its own implementation. */
  @Test
  @SuppressWarnings("deprecation") // This is a test for the deprecated function
  public void newKey_messageLite_works() throws Exception {
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(64)
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setHash(HashType.SHA512)
                    .setSalt(ByteString.copyFrom(new byte[] {1, 2, 3})))
            .build();
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(32).build();
    KeyTemplate derivedKeyTemplate =
        KeyTemplate.newBuilder()
            .setValue(format.toByteString())
            .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setOutputPrefixType(OutputPrefixType.RAW)
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.HkdfPrfKey")
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(PrfBasedDeriverParams.newBuilder().setDerivedKeyTemplate(derivedKeyTemplate))
            .build();

    // Calls the MessageLite overload of newKey
    PrfBasedDeriverKey prfBasedDeriverKey = (PrfBasedDeriverKey) manager.newKey(keyFormat);

    assertThat(prfBasedDeriverKey.getParams().getDerivedKeyTemplate())
        .isEqualTo(derivedKeyTemplate);
    assertThat(prfBasedDeriverKey.getPrfKey().getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.HkdfPrfKey");
    assertThat(prfBasedDeriverKey.getPrfKey().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.SYMMETRIC);
    HkdfPrfKey hkdfPrfKey =
        HkdfPrfKey.parseFrom(
            prfBasedDeriverKey.getPrfKey().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(hkdfPrfKey.getParams()).isEqualTo(prfKeyFormat.getParams());
    assertThat(hkdfPrfKey.getKeyValue()).hasSize(prfKeyFormat.getKeySize());
  }

  /** We test newKeyData directly because PrfBasedDeriverKeyManager has its own implementation. */
  @Test
  public void newKeyData_works() throws Exception {
    HkdfPrfKeyFormat prfKeyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(64)
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setHash(HashType.SHA512)
                    .setSalt(ByteString.copyFrom(new byte[] {1, 2, 3})))
            .build();
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(32).build();
    KeyTemplate derivedKeyTemplate =
        KeyTemplate.newBuilder()
            .setValue(format.toByteString())
            .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    PrfBasedDeriverKeyFormat keyFormat =
        PrfBasedDeriverKeyFormat.newBuilder()
            .setPrfKeyTemplate(
                KeyTemplate.newBuilder()
                    .setOutputPrefixType(OutputPrefixType.RAW)
                    .setTypeUrl("type.googleapis.com/google.crypto.tink.HkdfPrfKey")
                    .setValue(prfKeyFormat.toByteString()))
            .setParams(PrfBasedDeriverParams.newBuilder().setDerivedKeyTemplate(derivedKeyTemplate))
            .build();

    // Calls the MessageLite overload of newKey
    KeyData keyData = manager.newKeyData(keyFormat.toByteString());
    assertThat(keyData.getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
    PrfBasedDeriverKey parsedMessageLite =
        PrfBasedDeriverKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    assertThat(parsedMessageLite.getParams().getDerivedKeyTemplate()).isEqualTo(derivedKeyTemplate);
    assertThat(parsedMessageLite.getPrfKey().getTypeUrl())
        .isEqualTo("type.googleapis.com/google.crypto.tink.HkdfPrfKey");
    assertThat(parsedMessageLite.getPrfKey().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.SYMMETRIC);
    HkdfPrfKey hkdfPrfKey =
        HkdfPrfKey.parseFrom(
            parsedMessageLite.getPrfKey().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(hkdfPrfKey.getParams()).isEqualTo(prfKeyFormat.getParams());
    assertThat(hkdfPrfKey.getKeyValue()).hasSize(prfKeyFormat.getKeySize());
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test for the deprecated function
  public void testDoesSupport_works() throws Exception {
    assertTrue(manager.doesSupport("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"));
    assertFalse(manager.doesSupport("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  }

  @Test
  public void testGetKeyType_works() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  }

  @Test
  @SuppressWarnings("deprecation") // This is a test for the deprecated function
  public void testGetVersion() throws Exception {
    assertThat(manager.getVersion()).isEqualTo(0);
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
