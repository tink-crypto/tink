// Copyright 2024 Google LLC
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

package com.google.crypto.tink.hybrid;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.hybrid.internal.testing.LegacyHybridDecryptKeyManager;
import com.google.crypto.tink.hybrid.internal.testing.LegacyHybridEncryptKeyManager;
import com.google.crypto.tink.proto.HpkeAead;
import com.google.crypto.tink.proto.HpkeKdf;
import com.google.crypto.tink.proto.HpkeKem;
import com.google.crypto.tink.proto.HpkeParams;
import com.google.crypto.tink.proto.HpkePrivateKey;
import com.google.crypto.tink.proto.HpkePublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/**
 * This test attempts to test the case where a user registers their own key type with
 * Registry.registerKeyManager() and then uses it.
 */
@RunWith(Theories.class)
public final class KeyManagerIntegrationTest {
  private static final String PRIVATE_TYPE_URL = "type.googleapis.com/custom.HpkePrivateKey";
  private static final String PUBLIC_TYPE_URL = "type.googleapis.com/custom.HpkePublicKey";

  private static byte[] publicKeyByteArray;
  private static byte[] privateKeyByteArray;

  @BeforeClass
  public static void setUpClass() throws Exception {
    // We register Tink and key manger, as a user would typically do if they add their own key type.
    HybridConfig.register();
    // Register the key managers the user would register. These have type URLs PRIVATE_TYPE_URL and
    // PUBLIC_TYPE_URL, and interpret the keys as HpkePrivateKey and HpkePublicKey exactly
    // as Tink would. However, the parameters need to be:
    //  * DHKEM_X25519_HKDF_SHA256
    //  * HKDF_SHA256
    //  * AES_128_GCM
    Registry.registerKeyManager(new LegacyHybridDecryptKeyManager(), true);
    Registry.registerKeyManager(new LegacyHybridEncryptKeyManager(), false);

    publicKeyByteArray =
        Hex.decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    privateKeyByteArray =
        Hex.decode("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
  }

  private static HpkeParams getHpkeParams() {
    return HpkeParams.newBuilder()
        .setKem(HpkeKem.DHKEM_X25519_HKDF_SHA256)
        .setKdf(HpkeKdf.HKDF_SHA256)
        .setAead(HpkeAead.AES_128_GCM)
        .build();
  }

  private static HpkeParameters getParameters(HpkeParameters.Variant variant)
      throws GeneralSecurityException {
    return HpkeParameters.builder()
        .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
        .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
        .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
        .setVariant(variant)
        .build();
  }

  @Test
  public void testGetPublicKeyset_works() throws Exception {
    HpkePublicKey protoPublicKey =
        HpkePublicKey.newBuilder()
            .setVersion(0)
            .setParams(getHpkeParams())
            .setPublicKey(ByteString.copyFrom(publicKeyByteArray))
            .build();
    HpkePrivateKey protoPrivateKey =
        HpkePrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setPrivateKey(ByteString.copyFrom(privateKeyByteArray))
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(PRIVATE_TYPE_URL)
            .setValue(protoPrivateKey.toByteString())
            .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PRIVATE)
            .build();
    Keyset keyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(keyData)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(OutputPrefixType.TINK)
                    .setKeyId(0x23456789)
                    .build())
            .setPrimaryKeyId(0x23456789)
            .build();

    KeysetHandle handle =
        TinkProtoKeysetFormat.parseKeyset(keyset.toByteArray(), InsecureSecretKeyAccess.get());
    KeysetHandle publicHandle = handle.getPublicKeysetHandle();

    Keyset publicKeyset =
        Keyset.parseFrom(
            TinkProtoKeysetFormat.serializeKeysetWithoutSecret(publicHandle),
            ExtensionRegistryLite.getEmptyRegistry());

    assertThat(publicKeyset.getPrimaryKeyId()).isEqualTo(0x23456789);
    assertThat(publicKeyset.getKeyCount()).isEqualTo(1);
    assertThat(publicKeyset.getKey(0).getKeyId()).isEqualTo(0x23456789);
    assertThat(publicKeyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(publicKeyset.getKey(0).getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(publicKeyset.getKey(0).getKeyData().getTypeUrl()).isEqualTo(PUBLIC_TYPE_URL);
    assertThat(publicKeyset.getKey(0).getKeyData().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(
            HpkePublicKey.parseFrom(
                publicKeyset.getKey(0).getKeyData().getValue(),
                ExtensionRegistryLite.getEmptyRegistry()))
        .isEqualTo(protoPublicKey);
  }

  @DataPoints("allOutputPrefixTypes")
  public static final OutputPrefixType[] OUTPUT_PREFIX_TYPES =
      new OutputPrefixType[] {
        OutputPrefixType.LEGACY,
        OutputPrefixType.CRUNCHY,
        OutputPrefixType.TINK,
        OutputPrefixType.RAW
      };

  private static HpkeParameters.Variant variantForOutputPrefix(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case LEGACY:
      case CRUNCHY:
        return HpkeParameters.Variant.CRUNCHY;
      case TINK:
        return HpkeParameters.Variant.TINK;
      case RAW:
        return HpkeParameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException("Unknown output prefix type: " + outputPrefixType);
    }
  }

  /**
   * This test encrypts using a keyset with one key, with the custom key manager. It then decrypts
   * the ciphertext using normal Tink subtle HpkeDecrypt.
   */
  @Theory
  public void testEncryptCustom_decryptBuiltIn_works(
      @FromDataPoints("allOutputPrefixTypes") OutputPrefixType outputPrefixType) throws Exception {
    HpkePublicKey protoPublicKey =
        HpkePublicKey.newBuilder()
            .setVersion(0)
            .setParams(getHpkeParams())
            .setPublicKey(ByteString.copyFrom(publicKeyByteArray))
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(PUBLIC_TYPE_URL)
            .setValue(protoPublicKey.toByteString())
            .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PUBLIC)
            .build();
    Keyset keyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(keyData)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(outputPrefixType)
                    .setKeyId(0x23456789)
                    .build())
            .setPrimaryKeyId(0x23456789)
            .build();

    KeysetHandle handle = TinkProtoKeysetFormat.parseKeysetWithoutSecret(keyset.toByteArray());
    HybridEncrypt customEncrypter = handle.getPrimitive(HybridEncrypt.class);

    byte[] message = new byte[] {1, 2, 3};
    byte[] context = new byte[] {4};
    byte[] ciphertext = customEncrypter.encrypt(message, context);

    @Nullable Integer idRequirement = outputPrefixType == OutputPrefixType.RAW ? null : 0x23456789;
    HybridDecrypt tinkDecrypter =
        HpkeDecrypt.create(
            com.google.crypto.tink.hybrid.HpkePrivateKey.create(
                com.google.crypto.tink.hybrid.HpkePublicKey.create(
                    getParameters(variantForOutputPrefix(outputPrefixType)),
                    Bytes.copyFrom(publicKeyByteArray),
                    idRequirement),
                SecretBytes.copyFrom(privateKeyByteArray, InsecureSecretKeyAccess.get())));
    assertThat(tinkDecrypter.decrypt(ciphertext, context)).isEqualTo(message);
  }

  /**
   * This encrypts using the subtle Tink API, then decrypts using the custom key manager with a
   * keyset with a single key.
   */
  @Theory
  public void testDecryptCustom_encryptBuiltIn_works(
      @FromDataPoints("allOutputPrefixTypes") OutputPrefixType outputPrefixType) throws Exception {
    HpkePublicKey protoPublicKey =
        HpkePublicKey.newBuilder()
            .setVersion(0)
            .setParams(getHpkeParams())
            .setPublicKey(ByteString.copyFrom(publicKeyByteArray))
            .build();
    HpkePrivateKey protoPrivateKey =
        HpkePrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setPrivateKey(ByteString.copyFrom(privateKeyByteArray))
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(PRIVATE_TYPE_URL)
            .setValue(protoPrivateKey.toByteString())
            .setKeyMaterialType(KeyMaterialType.ASYMMETRIC_PRIVATE)
            .build();
    Keyset keyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(keyData)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(outputPrefixType)
                    .setKeyId(0x23456789)
                    .build())
            .setPrimaryKeyId(0x23456789)
            .build();

    KeysetHandle handle =
        TinkProtoKeysetFormat.parseKeyset(keyset.toByteArray(), InsecureSecretKeyAccess.get());
    HybridDecrypt customDecrypter = handle.getPrimitive(HybridDecrypt.class);

    byte[] message = new byte[] {1, 2, 3};
    byte[] context = new byte[] {4};

    @Nullable Integer idRequirement = outputPrefixType == OutputPrefixType.RAW ? null : 0x23456789;
    HybridEncrypt tinkEncrypter =
        HpkeEncrypt.create(
            com.google.crypto.tink.hybrid.HpkePublicKey.create(
                getParameters(variantForOutputPrefix(outputPrefixType)),
                Bytes.copyFrom(publicKeyByteArray),
                idRequirement));
    byte[] ciphertext = tinkEncrypter.encrypt(message, context);
    assertThat(customDecrypter.decrypt(ciphertext, context)).isEqualTo(message);
  }
}
