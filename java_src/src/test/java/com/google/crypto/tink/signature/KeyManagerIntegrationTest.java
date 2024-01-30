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

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.proto.Ed25519KeyFormat;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.internal.testing.LegacyPublicKeySignKeyManager;
import com.google.crypto.tink.signature.internal.testing.LegacyPublicKeyVerifyKeyManager;
import com.google.crypto.tink.subtle.Ed25519Sign;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
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
  private static final String PRIVATE_TYPE_URL = "type.googleapis.com/custom.Ed25519PrivateKey";
  private static final String PUBLIC_TYPE_URL = "type.googleapis.com/custom.Ed25519PublicKey";

  private static byte[] publicKeyByteArray;
  private static byte[] privateKeyByteArray;

  @BeforeClass
  public static void setUpClass() throws Exception {
    // We register Tink and key manger, as a user would typically do if they add their own key type.
    SignatureConfig.register();
    // Register the key managers the user would register. These have type URLs PRIVATE_TYPE_URL and
    // PUBLIC_TYPE_URL, and interpret the keys as Ed25519PrivateKey and Ed25519PublicKey exactly
    // as Tink would.
    Registry.registerKeyManager(new LegacyPublicKeySignKeyManager(), true);
    Registry.registerKeyManager(new LegacyPublicKeyVerifyKeyManager(), false);

    publicKeyByteArray =
        Hex.decode("ea42941a6dc801484390b2955bc7376d172eeb72640a54e5b50c95efa2fc6ad8");
    privateKeyByteArray =
        Hex.decode("9cac7d19aeecc563a3dff7bcae0fbbbc28087b986c49a3463077dd5281437e81");
  }

  @Test
  public void testGetPublicKeyset_works() throws Exception {
    Ed25519PublicKey protoPublicKey =
        Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(publicKeyByteArray))
            .build();
    Ed25519PrivateKey protoPrivateKey =
        Ed25519PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setKeyValue(ByteString.copyFrom(privateKeyByteArray))
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
            Ed25519PublicKey.parseFrom(
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

  private static Ed25519Parameters.Variant variantForOutputPrefix(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    switch (outputPrefixType) {
      case LEGACY:
        return Ed25519Parameters.Variant.LEGACY;
      case CRUNCHY:
        return Ed25519Parameters.Variant.CRUNCHY;
      case TINK:
        return Ed25519Parameters.Variant.TINK;
      case RAW:
        return Ed25519Parameters.Variant.NO_PREFIX;
      default:
        throw new GeneralSecurityException("Unknown output prefix type: " + outputPrefixType);
    }
  }

  /**
   * This test computes the signature using a keyset with one key, with the custom key manager. It
   * then verifies the Signature using normal Tink subtle Ed25519Verify.
   */
  @Theory
  public void testComputeCustom_verifyBuiltIn_works(
      @FromDataPoints("allOutputPrefixTypes") OutputPrefixType outputPrefixType) throws Exception {
    Ed25519PublicKey protoPublicKey =
        Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(publicKeyByteArray))
            .build();
    Ed25519PrivateKey protoPrivateKey =
        Ed25519PrivateKey.newBuilder()
            .setVersion(0)
            .setPublicKey(protoPublicKey)
            .setKeyValue(ByteString.copyFrom(privateKeyByteArray))
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
    PublicKeySign customSigner = handle.getPrimitive(PublicKeySign.class);

    byte[] message = new byte[] {1, 2, 3};
    byte[] signature = customSigner.sign(message);

    @Nullable Integer idRequirement = outputPrefixType == OutputPrefixType.RAW ? null : 0x23456789;
    PublicKeyVerify tinkVerifier =
        Ed25519Verify.create(
            com.google.crypto.tink.signature.Ed25519PublicKey.create(
                variantForOutputPrefix(outputPrefixType),
                Bytes.copyFrom(publicKeyByteArray),
                idRequirement));

    tinkVerifier.verify(signature, message);
  }

  /**
   * This test computes the signature using a Tink subtle Ed25519Sign. It then verifies the
   * Signature with a PublicKeyVerify from the custom keyset.
   */
  @Theory
  public void testComputeBuiltIn_verifyCustom_works(
      @FromDataPoints("allOutputPrefixTypes") OutputPrefixType outputPrefixType) throws Exception {
    Ed25519PublicKey protoPublicKey =
        Ed25519PublicKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(publicKeyByteArray))
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
    PublicKeyVerify customVerifier = handle.getPrimitive(PublicKeyVerify.class);
    @Nullable Integer idRequirement = outputPrefixType == OutputPrefixType.RAW ? null : 0x23456789;

    PublicKeySign tinkSigner =
        Ed25519Sign.create(
            com.google.crypto.tink.signature.Ed25519PrivateKey.create(
                com.google.crypto.tink.signature.Ed25519PublicKey.create(
                    variantForOutputPrefix(outputPrefixType),
                    Bytes.copyFrom(publicKeyByteArray),
                    idRequirement),
                SecretBytes.copyFrom(privateKeyByteArray, InsecureSecretKeyAccess.get())));

    byte[] message = new byte[] {1, 2, 3};
    byte[] signature = tinkSigner.sign(message);
    customVerifier.verify(signature, message);
  }

  @Theory
  public void testKeyGeneration_givesNewKeys_works(
      @FromDataPoints("allOutputPrefixTypes") OutputPrefixType outputPrefixType) throws Exception {

    KeyTemplate protoKeyTemplate =
        KeyTemplate.newBuilder()
            .setOutputPrefixType(outputPrefixType)
            .setTypeUrl(PRIVATE_TYPE_URL)
            .setValue(Ed25519KeyFormat.getDefaultInstance().toByteString())
            .build();
    Parameters parameters = TinkProtoParametersFormat.parse(protoKeyTemplate.toByteArray());

    Set<String> keys = new TreeSet<>();
    int numKeys = 20;

    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle =
          KeysetHandle.newBuilder()
              .addEntry(
                  KeysetHandle.generateEntryFromParameters(parameters)
                      .withFixedId(0x88117722)
                      .makePrimary())
              .build();

      Keyset keyset =
          Keyset.parseFrom(
              TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get()),
              ExtensionRegistryLite.getEmptyRegistry());
      assertThat(keyset.getPrimaryKeyId()).isEqualTo(0x88117722);
      assertThat(keyset.getKeyCount()).isEqualTo(1);
      assertThat(keyset.getKey(0).getKeyId()).isEqualTo(0x88117722);
      assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
      assertThat(keyset.getKey(0).getOutputPrefixType()).isEqualTo(outputPrefixType);
      assertThat(keyset.getKey(0).getKeyData().getTypeUrl()).isEqualTo(PRIVATE_TYPE_URL);
      assertThat(keyset.getKey(0).getKeyData().getKeyMaterialType())
          .isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
      Ed25519PrivateKey privateKey =
          Ed25519PrivateKey.parseFrom(
              keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
      keys.add(Hex.encode(privateKey.getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numKeys);
  }
}
