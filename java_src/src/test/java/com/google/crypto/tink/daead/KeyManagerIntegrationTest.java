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

package com.google.crypto.tink.daead;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;

import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.daead.internal.testing.LegacyAesSivTestKeyManager;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.proto.AesSivKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.security.GeneralSecurityException;
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
  private static final String TYPE_URL = "type.googleapis.com/custom.AesSivKey";
  private static final byte[] KEY_BYTES = Random.randBytes(64);
  private static final int KEY_ID = 0x23456789;
  private static final EnumTypeProtoConverter<OutputPrefixType, AesSivParameters.Variant>
      OUTPUT_PREFIX_TYPE_CONVERTER =
          EnumTypeProtoConverter.<OutputPrefixType, AesSivParameters.Variant>builder()
              .add(OutputPrefixType.RAW, AesSivParameters.Variant.NO_PREFIX)
              .add(OutputPrefixType.TINK, AesSivParameters.Variant.TINK)
              .add(OutputPrefixType.CRUNCHY, AesSivParameters.Variant.CRUNCHY)
              .add(OutputPrefixType.LEGACY, AesSivParameters.Variant.CRUNCHY)
              .build();

  @BeforeClass
  public static void setUpClass() throws Exception {
    // Register Tink and the key manger, as a user would typically do if they add their own key
    // type.
    DeterministicAeadConfig.register();
    // Register the key manager the user would register. This has the type url TYPE_URL and
    // interprets the key as AesSivKey exactly as Tink would.
    Registry.registerKeyManager(new LegacyAesSivTestKeyManager(), true);
  }

  @Test
  public void parseFromKeyset_works() throws Exception {
    AesSivKey protoKey =
        AesSivKey.newBuilder().setVersion(0).setKeyValue(ByteString.copyFrom(KEY_BYTES)).build();
    KeysetHandle handle = getKeysetHandleFromProtoKey(protoKey, OutputPrefixType.TINK);

    Keyset keyset =
        Keyset.parseFrom(
            TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get()),
            ExtensionRegistryLite.getEmptyRegistry());

    assertThat(keyset.getPrimaryKeyId()).isEqualTo(KEY_ID);
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyId()).isEqualTo(KEY_ID);
    assertThat(keyset.getKey(0).getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(keyset.getKey(0).getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(keyset.getKey(0).getKeyData().getTypeUrl()).isEqualTo(TYPE_URL);
    assertThat(keyset.getKey(0).getKeyData().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.SYMMETRIC);
    assertThat(
            AesSivKey.parseFrom(
                keyset.getKey(0).getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry()))
        .isEqualTo(protoKey);
  }

  @DataPoints("allOutputPrefixTypes")
  public static final OutputPrefixType[] OUTPUT_PREFIX_TYPES =
      new OutputPrefixType[] {
        OutputPrefixType.CRUNCHY,
        OutputPrefixType.TINK,
        OutputPrefixType.RAW,
        OutputPrefixType.LEGACY
      };

  /**
   * Encrypts using a keyset with one key, with the custom key manager and decrypts the ciphertext
   * using normal Tink subtle decryptDeterministically.
   */
  @Theory
  public void encryptCustom_decryptBuiltIn_works(
      @FromDataPoints("allOutputPrefixTypes") OutputPrefixType outputPrefixType) throws Exception {
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    AesSivKey protoKey =
        AesSivKey.newBuilder().setVersion(0).setKeyValue(ByteString.copyFrom(KEY_BYTES)).build();
    KeysetHandle handle = getKeysetHandleFromProtoKey(protoKey, outputPrefixType);

    DeterministicAead customDaead = handle.getPrimitive(DeterministicAead.class);
    byte[] ciphertext = customDaead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = customDaead.encryptDeterministically(plaintext, associatedData);
    DeterministicAead tinkDaead = AesSiv.create(createKey(outputPrefixType));
    byte[] decrypted = tinkDaead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = tinkDaead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);
  }

  /**
   * This encrypts using the subtle Tink API, then decrypts using the custom key manager with a
   * keyset with a single key.
   */
  @Theory
  public void encryptBuiltIn_decryptCustom_works(
      @FromDataPoints("allOutputPrefixTypes") OutputPrefixType outputPrefixType) throws Exception {
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    DeterministicAead tinkDaead = AesSiv.create(createKey(outputPrefixType));
    byte[] ciphertext = tinkDaead.encryptDeterministically(plaintext, associatedData);
    byte[] ciphertext2 = tinkDaead.encryptDeterministically(plaintext, associatedData);
    AesSivKey protoKey =
        AesSivKey.newBuilder().setVersion(0).setKeyValue(ByteString.copyFrom(KEY_BYTES)).build();
    KeysetHandle handle = getKeysetHandleFromProtoKey(protoKey, outputPrefixType);
    DeterministicAead customDaead = handle.getPrimitive(DeterministicAead.class);
    byte[] decrypted = customDaead.decryptDeterministically(ciphertext, associatedData);
    byte[] decrypted2 = customDaead.decryptDeterministically(ciphertext2, associatedData);

    assertArrayEquals(ciphertext, ciphertext2);
    assertArrayEquals(plaintext, decrypted);
    assertArrayEquals(plaintext, decrypted2);
  }

  private static KeysetHandle getKeysetHandleFromProtoKey(
      AesSivKey protoKey, OutputPrefixType outputPrefixType) throws GeneralSecurityException {
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(TYPE_URL)
            .setValue(protoKey.toByteString())
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .build();
    Keyset keyset =
        Keyset.newBuilder()
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyData(keyData)
                    .setStatus(KeyStatusType.ENABLED)
                    .setOutputPrefixType(outputPrefixType)
                    .setKeyId(KEY_ID)
                    .build())
            .setPrimaryKeyId(KEY_ID)
            .build();

    return TinkProtoKeysetFormat.parseKeyset(keyset.toByteArray(), InsecureSecretKeyAccess.get());
  }

  private static com.google.crypto.tink.daead.AesSivKey createKey(OutputPrefixType outputPrefixType)
      throws GeneralSecurityException {
    return com.google.crypto.tink.daead.AesSivKey.builder()
        .setParameters(
            AesSivParameters.builder()
                .setKeySizeBytes(64)
                .setVariant(OUTPUT_PREFIX_TYPE_CONVERTER.fromProtoEnum(outputPrefixType))
                .build())
        .setKeyBytes(SecretBytes.copyFrom(KEY_BYTES, InsecureSecretKeyAccess.get()))
        .setIdRequirement(outputPrefixType == OutputPrefixType.RAW ? null : KEY_ID)
        .build();
  }
}
