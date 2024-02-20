// Copyright 2022 Google LLC
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

package com.google.crypto.tink.mac;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.internal.PrimitiveRegistry;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.HmacParameters.HashType;
import com.google.crypto.tink.mac.internal.HmacProtoSerialization;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ChunkedMacWrapperTest {
  private static final int HMAC_KEY_SIZE = 20;
  private static final int HMAC_TAG_SIZE = 10;
  private static final int AES_CMAC_KEY_SIZE = 32;
  private static final int AES_CMAC_TAG_SIZE = 10;

  private static HmacKey rawKey0;
  private static HmacKey rawKey1;
  private static AesCmacKey rawKey2;
  private static AesCmacKey rawKey3;
  private static HmacKey tinkKey0;
  private static AesCmacKey tinkKey1;
  private static HmacKey crunchyKey0;
  private static AesCmacKey crunchyKey1;
  private static HmacKey legacyKey0;
  private static AesCmacKey legacyKey1;

  @BeforeClass
  public static void setUp() throws Exception {
    MacConfig.register();
    AesCmacProtoSerialization.register();
    HmacProtoSerialization.register();
    ChunkedMacWrapper.register();
    createTestKeys();
  }

  private static void createTestKeys() {
    final HmacParameters noPrefixHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.NO_PREFIX);
    final HmacParameters legacyHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.LEGACY);
    final HmacParameters crunchyHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.CRUNCHY);
    final HmacParameters tinkHmacParameters =
        createDefaultHmacParameters(HmacParameters.Variant.TINK);
    final AesCmacParameters noPrefixAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.NO_PREFIX);
    final AesCmacParameters legacyAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.LEGACY);
    final AesCmacParameters crunchyAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.CRUNCHY);
    final AesCmacParameters tinkAesCmacParameters =
        createDefaultAesCmacParameters(AesCmacParameters.Variant.TINK);

    try {
      rawKey0 =
          HmacKey.builder()
              .setParameters(noPrefixHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
      rawKey1 =
          HmacKey.builder()
              .setParameters(noPrefixHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
      rawKey2 =
          AesCmacKey.builder()
              .setParameters(noPrefixAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
      rawKey3 =
          AesCmacKey.builder()
              .setParameters(noPrefixAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(null)
              .build();
      tinkKey0 =
          HmacKey.builder()
              .setParameters(tinkHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(4)
              .build();
      tinkKey1 =
          AesCmacKey.builder()
              .setParameters(tinkAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(5)
              .build();
      crunchyKey0 =
          HmacKey.builder()
              .setParameters(crunchyHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(6)
              .build();
      crunchyKey1 =
          AesCmacKey.builder()
              .setParameters(crunchyAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(7)
              .build();
      legacyKey0 =
          HmacKey.builder()
              .setParameters(legacyHmacParameters)
              .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
              .setIdRequirement(8)
              .build();
      legacyKey1 =
          AesCmacKey.builder()
              .setParameters(legacyAesCmacParameters)
              .setAesKeyBytes(SecretBytes.randomBytes(AES_CMAC_KEY_SIZE))
              .setIdRequirement(9)
              .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static AesCmacParameters createDefaultAesCmacParameters(Variant variant) {
    try {
      return AesCmacParameters.builder()
          .setKeySizeBytes(AES_CMAC_KEY_SIZE)
          .setTagSizeBytes(AES_CMAC_TAG_SIZE)
          .setVariant(variant)
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static HmacParameters createDefaultHmacParameters(HmacParameters.Variant variant) {
    try {
      return HmacParameters.builder()
          .setKeySizeBytes(HMAC_KEY_SIZE)
          .setTagSizeBytes(HMAC_TAG_SIZE)
          .setVariant(variant)
          .setHashType(HashType.SHA1)
          .build();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Incorrect parameters creation arguments", e);
    }
  }

  @Test
  public void testComputeVerifyMac_works() throws Exception {
    ByteBuffer plaintext = ByteBuffer.wrap("plaintext".getBytes(UTF_8));
    KeysetHandle smallKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234).makePrimary())
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .build();

    ChunkedMac mac = smallKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(plaintext);
    byte[] tag = macComputation.computeMac();

    plaintext.rewind();
    ChunkedMacVerification macVerification = mac.createVerification(tag);
    macVerification.update(plaintext);

    macVerification.verifyMac();
  }

  @Test
  public void testComputeVerifyMac_throwsOnWrongKey() throws Exception {
    ByteBuffer plaintext = ByteBuffer.wrap("plaintext".getBytes(UTF_8));
    KeysetHandle computeKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234).makePrimary())
            .build();
    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235).makePrimary())
            .build();

    ChunkedMac mac0 = computeKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacComputation macComputation = mac0.createComputation();
    macComputation.update(plaintext);
    byte[] tag = macComputation.computeMac();

    plaintext.rewind();
    ChunkedMac mac1 = verifyKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification macVerification = mac1.createVerification(tag);
    macVerification.update(plaintext);

    assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
  }

  @Test
  public void testComputeVerifyMac_handlesByteBufferCorrectly() throws Exception {
    ByteBuffer verificationPlaintext =
        (ByteBuffer) ByteBuffer.wrap("plaintext".getBytes(UTF_8)).position(3).limit(6);
    ByteBuffer computationPlaintext = ByteBuffer.wrap("int".getBytes(UTF_8));

    KeysetHandle computeKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237).makePrimary())
            .build();
    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .build();

    ChunkedMac mac = computeKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(computationPlaintext);
    byte[] tag = macComputation.computeMac();

    ChunkedMac mac1 = verifyKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification macVerification = mac1.createVerification(tag);
    macVerification.update(verificationPlaintext);

    macVerification.verifyMac();
    assertThat(computationPlaintext.position()).isEqualTo(computationPlaintext.limit());
    assertThat(verificationPlaintext.position()).isEqualTo(verificationPlaintext.limit());
  }

  @Test
  public void testVerifyMac_handlesByteBufferCorrectlyWhenNoKeyMatches() throws Exception {
    ByteBuffer verificationPlaintext = ByteBuffer.wrap("plaintext".getBytes(UTF_8));
    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(tinkKey0).makePrimary())
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .build();
    byte[] tag = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    ChunkedMac mac = verifyKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification macVerification = mac.createVerification(tag);
    macVerification.update(verificationPlaintext);

    assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
    assertThat(verificationPlaintext.position()).isEqualTo(verificationPlaintext.limit());
  }

  @Test
  public void testVerifyMac_checksAllNecessaryRawKeys() throws Exception {
    ByteBuffer plaintext = ByteBuffer.wrap("plaintext".getBytes(UTF_8));
    KeysetHandle computeKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237).makePrimary())
            .build();
    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .build();

    ChunkedMac mac = computeKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(plaintext);
    byte[] tag = macComputation.computeMac();

    plaintext.rewind();
    ChunkedMac mac1 = verifyKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification macVerification = mac1.createVerification(tag);
    macVerification.update(plaintext);

    macVerification.verifyMac();
  }

  @Test
  public void testVerifyMac_suppressedExceptionsGetPropagated() throws Exception {
    byte[] fakeTag =
        ByteBuffer.allocate(AES_CMAC_TAG_SIZE)
            .put(tinkKey1.getOutputPrefix().toByteArray())
            .put(new byte[] {0, 0, 0, 0, 0})
            .array();

    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235))
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey1).makePrimary())
            .build();

    ChunkedMac mac = verifyKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification macVerification = mac.createVerification(fakeTag);
    macVerification.update(ByteBuffer.wrap("plaintext".getBytes(UTF_8)));

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, macVerification::verifyMac);
    assertThat(e.getSuppressed()).hasLength(3);
  }

  @Test
  public void testVerifyMac_checksRawKeysWhenTagHasTinkKeyPrefix() throws Exception {
    // Plaintext: "plaintext".getBytes(UTF_8)
    byte[] tag = Hex.decode("0152af9740d2fab0cf3f");
    // 0x52af9740, which equals 1387239232.
    int id = ByteBuffer.wrap(tag, 1, 4).getInt();
    HmacKey rawKey5 =
        HmacKey.builder()
            .setParameters(createDefaultHmacParameters(HmacParameters.Variant.NO_PREFIX))
            .setKeyBytes(
                SecretBytes.copyFrom(
                    Hex.decode("7d40a4d7c192ca113f403b8703e1b7b93fecf99a"),
                    InsecureSecretKeyAccess.get()))
            .setIdRequirement(null)
            .build();
    HmacKey tinkKey2 =
        HmacKey.builder()
            .setParameters(createDefaultHmacParameters(HmacParameters.Variant.TINK))
            .setKeyBytes(SecretBytes.randomBytes(HMAC_KEY_SIZE))
            .setIdRequirement(id)
            .build();
    KeysetHandle verifyKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey5).withFixedId(1235))
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey2).makePrimary())
            .build();

    ChunkedMac mac = verifyKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification macVerification = mac.createVerification(tag);
    macVerification.update(ByteBuffer.wrap("plaintext".getBytes(UTF_8)));

    macVerification.verifyMac();
  }

  @Test
  public void testComputeMac_usesPrimaryKey() throws Exception {
    ByteBuffer plaintext = ByteBuffer.wrap("plaintext".getBytes(UTF_8));
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236).makePrimary())
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .build();
    KeysetHandle keysetHandlePrimary =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236).makePrimary())
            .build();

    ChunkedMac mac = keysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(plaintext);
    byte[] tag = macComputation.computeMac();

    plaintext.rewind();
    ChunkedMac primaryMac = keysetHandlePrimary.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification primaryMacVerification = primaryMac.createVerification(tag);
    primaryMacVerification.update(plaintext);

    primaryMacVerification.verifyMac();
  }

  @Test
  public void testComputeVerifyMac_manyKeysWork() throws Exception {
    ByteBuffer plaintext = ByteBuffer.wrap("plaintext".getBytes(UTF_8));
    KeysetHandle assortedKeysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234))
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235))
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236))
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey0))
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .addEntry(KeysetHandle.importKey(crunchyKey0))
            .addEntry(KeysetHandle.importKey(crunchyKey1).makePrimary())
            .addEntry(KeysetHandle.importKey(legacyKey0))
            .addEntry(KeysetHandle.importKey(legacyKey1))
            .build();

    ChunkedMac mac = assortedKeysetHandle.getPrimitive(ChunkedMac.class);
    ChunkedMacComputation macComputation = mac.createComputation();
    macComputation.update(plaintext);
    byte[] tag = macComputation.computeMac();

    plaintext.rewind();
    ChunkedMacVerification macVerification = mac.createVerification(tag);
    macVerification.update(plaintext);

    macVerification.verifyMac();
  }

  @Test
  public void testVerifyMac_shiftedPrimaryWithManyKeysWorks() throws Exception {
    ByteBuffer plaintext = ByteBuffer.wrap("plaintext".getBytes(UTF_8));
    KeysetHandle assortedKeysetHandle0 =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(rawKey0).withFixedId(1234))
            .addEntry(KeysetHandle.importKey(rawKey1).withFixedId(1235))
            .addEntry(KeysetHandle.importKey(rawKey2).withFixedId(1236))
            .addEntry(KeysetHandle.importKey(rawKey3).withFixedId(1237))
            .addEntry(KeysetHandle.importKey(tinkKey0))
            .addEntry(KeysetHandle.importKey(tinkKey1))
            .addEntry(KeysetHandle.importKey(crunchyKey0))
            .addEntry(KeysetHandle.importKey(crunchyKey1).makePrimary())
            .addEntry(KeysetHandle.importKey(legacyKey0))
            .addEntry(KeysetHandle.importKey(legacyKey1))
            .build();
    KeysetHandle.Builder assortedBuilder = KeysetHandle.newBuilder(assortedKeysetHandle0);
    assortedBuilder.getAt(4).makePrimary();
    KeysetHandle assortedKeysetHandle1 = assortedBuilder.build();

    ChunkedMac mac0 = assortedKeysetHandle0.getPrimitive(ChunkedMac.class);
    ChunkedMacComputation macComputation = mac0.createComputation();
    macComputation.update(plaintext);
    byte[] tag = macComputation.computeMac();

    plaintext.rewind();
    ChunkedMac mac1 = assortedKeysetHandle1.getPrimitive(ChunkedMac.class);
    ChunkedMacVerification macVerification = mac1.createVerification(tag);
    macVerification.update(plaintext);

    macVerification.verifyMac();
  }

  @Test
  public void registerToInternalPrimitiveRegistry_works() throws Exception {
    PrimitiveRegistry.Builder initialBuilder = PrimitiveRegistry.builder();
    PrimitiveRegistry initialRegistry = initialBuilder.build();
    PrimitiveRegistry.Builder processedBuilder = PrimitiveRegistry.builder(initialRegistry);

    ChunkedMacWrapper.registerToInternalPrimitiveRegistry(processedBuilder);
    PrimitiveRegistry processedRegistry = processedBuilder.build();

    assertThrows(
        GeneralSecurityException.class,
        () -> initialRegistry.getInputPrimitiveClass(ChunkedMac.class));
    assertThat(processedRegistry.getInputPrimitiveClass(ChunkedMac.class))
        .isEqualTo(ChunkedMac.class);
  }
}
