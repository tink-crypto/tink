// Copyright 2023 Google LLC
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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AesEaxKey;
import com.google.crypto.tink.aead.AesEaxParameters;
import com.google.crypto.tink.aead.AesEaxParameters.Variant;
import com.google.crypto.tink.mac.ChunkedMac;
import com.google.crypto.tink.mac.ChunkedMacComputation;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.HmacParameters;
import com.google.crypto.tink.mac.HmacParameters.HashType;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.internal.LegacyFullMac;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link RegistryConfiguration}. */
@RunWith(JUnit4.class)
public class RegistryConfigurationTest {
  private static final int HMAC_KEY_SIZE = 20;
  private static final int HMAC_TAG_SIZE = 10;

  private static HmacKey rawKey;
  private static KeyData rawKeyData;
  private static Keyset.Key rawKeysetKey;
  private static LegacyProtoKey legacyProtoRawKey;

  @Before
  public void setUp() throws GeneralSecurityException {
    MacConfig.register();
    createTestKeys();
  }

  private static void createTestKeys() {
    try {
      rawKey =
          HmacKey.builder()
              .setParameters(
                  HmacParameters.builder()
                      .setKeySizeBytes(HMAC_KEY_SIZE)
                      .setTagSizeBytes(HMAC_TAG_SIZE)
                      .setVariant(HmacParameters.Variant.NO_PREFIX)
                      .setHashType(HashType.SHA256)
                      .build())
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();

      // Create the proto key artefacts.
      KeysetHandle keysetHandle =
          KeysetHandle.newBuilder()
              .addEntry(KeysetHandle.importKey(rawKey).withRandomId().makePrimary())
              .build();
      rawKeyData =
          KeyData.newBuilder()
              .setValue(
                  com.google.crypto.tink.proto.HmacKey.newBuilder()
                      .setParams(
                          HmacParams.newBuilder()
                              .setHash(com.google.crypto.tink.proto.HashType.SHA256)
                              .setTagSize(HMAC_TAG_SIZE)
                              .build())
                      .setKeyValue(
                          ByteString.copyFrom(
                              rawKey.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())))
                      .build()
                      .toByteString())
              .setTypeUrl(keysetHandle.getKeysetInfo().getKeyInfo(0).getTypeUrl())
              .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
              .build();
      rawKeysetKey =
          Keyset.Key.newBuilder()
              .setKeyData(rawKeyData)
              .setStatus(KeyStatusType.ENABLED)
              .setKeyId(keysetHandle.getKeysetInfo().getPrimaryKeyId())
              .setOutputPrefixType(OutputPrefixType.RAW)
              .build();
      legacyProtoRawKey =
          new LegacyProtoKey(
              MutableSerializationRegistry.globalInstance()
                  .serializeKey(rawKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get()),
              InsecureSecretKeyAccess.get());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  @Test
  public void getLegacyPrimitive_matchesRegistry() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Mac configurationMac =
        RegistryConfiguration.get().getLegacyPrimitive(rawKeyData, Mac.class);
    Mac registryMac = Registry.getPrimitive(rawKeyData, Mac.class);

    assertThat(configurationMac.computeMac(plaintext)).isEqualTo(registryMac.computeMac(plaintext));
  }

  @Test
  public void getPrimitive_matchesRegistry() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    ChunkedMac configurationMac =
        RegistryConfiguration.get().getPrimitive(rawKey, ChunkedMac.class);
    ChunkedMacComputation configurationComputation = configurationMac.createComputation();
    ChunkedMac registryMac =
        MutablePrimitiveRegistry.globalInstance().getPrimitive(rawKey, ChunkedMac.class);
    ChunkedMacComputation registryComputation = registryMac.createComputation();

    configurationComputation.update(ByteBuffer.wrap(plaintext));
    registryComputation.update(ByteBuffer.wrap(plaintext));

    assertThat(configurationComputation.computeMac()).isEqualTo(registryComputation.computeMac());
  }

  @Test
  public void wrap_matchesRegistry() throws Exception {
    byte[] plaintext = "plaintext".getBytes(UTF_8);

    Mac registryMac = Registry.getPrimitive(rawKeyData, Mac.class);
    // The following relies on the fact that internally LegacyFullMac uses RegistryConfiguration.
    Mac wrappedConfigurationMac =
        RegistryConfiguration.get()
            .wrap(
                PrimitiveSet.newBuilder(Mac.class)
                    .addPrimaryFullPrimitiveAndOptionalPrimitive(
                        LegacyFullMac.create(legacyProtoRawKey), null, rawKeysetKey)
                    .build(),
                Mac.class);

    assertThat(wrappedConfigurationMac.computeMac(plaintext))
        .isEqualTo(registryMac.computeMac(plaintext));
  }

  @Test
  public void getInputPrimitiveClass_matchesRegistry() throws Exception {
    assertThat(RegistryConfiguration.get().getInputPrimitiveClass(ChunkedMac.class))
        .isEqualTo(Registry.getInputPrimitive(ChunkedMac.class));
  }

  @Test
  public void getInputPrimitiveClass_returnsNullOnUnregisteredPrimitive() throws Exception {
    assertThat(RegistryConfiguration.get().getInputPrimitiveClass(Aead.class))
        .isNull();
  }

  @Test
  public void requestingUnregisteredPrimitives_throws() throws GeneralSecurityException {
    AesEaxKey aesEaxKey =
        AesEaxKey.builder()
            .setKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(1234)
            .setParameters(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setTagSizeBytes(16)
                    .setKeySizeBytes(32)
                    .setVariant(Variant.TINK)
                    .build())
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> RegistryConfiguration.get().getPrimitive(aesEaxKey, Aead.class));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            RegistryConfiguration.get()
                .wrap(PrimitiveSet.newBuilder(Aead.class).build(), Aead.class));
  }
}
