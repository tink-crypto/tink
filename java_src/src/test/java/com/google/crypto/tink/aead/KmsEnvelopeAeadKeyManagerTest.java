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

package com.google.crypto.tink.aead;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.Util.isPrefix;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.aead.LegacyKmsEnvelopeAeadParameters.DekParsingStrategy;
import com.google.crypto.tink.aead.internal.AesGcmSivProtoSerialization;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.FakeKmsClient;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ExtensionRegistryLite;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.annotation.Nullable;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@code KmsEnvelopeAead} and {@code KmsEnvelopeAeadKeyManager}. */
@RunWith(JUnit4.class)
public class KmsEnvelopeAeadKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    KmsClients.add(new FakeKmsClient());
    AeadConfig.register();
    AesGcmSivProtoSerialization.register();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager(
                    "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey", Aead.class))
        .isNotNull();
  }

  @Test
  public void getPrimitiveFromLegacyKmsEnvelopeAeadKey_works() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri(kekUri)
            .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_EAX)
            .setDekParametersForNewKeys(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    LegacyKmsEnvelopeAeadKey key = LegacyKmsEnvelopeAeadKey.create(parameters);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    Aead aead = keysetHandle.getPrimitive(Aead.class);

    TestUtil.runBasicAeadTests(aead);

    // Also check that aead is compatible with an Aead created with KmsEnvelopeAead.create().
    Aead keyEncryptionAead = new FakeKmsClient().getAead(kekUri);
    Aead aead2 = KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_EAX, keyEncryptionAead);
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    byte[] decrypted = aead2.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void getPrimitiveFromLegacyKmsEnvelopeAeadKeyWithTinkPrefix_works() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setVariant(LegacyKmsEnvelopeAeadParameters.Variant.TINK)
            .setKekUri(kekUri)
            .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_EAX)
            .setDekParametersForNewKeys(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    LegacyKmsEnvelopeAeadKey key =
        LegacyKmsEnvelopeAeadKey.create(parameters, /* idRequirement= */ 0xbbccddee);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(0xbbccddee).makePrimary())
            .build();

    Aead aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    TestUtil.runBasicAeadTests(aead);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertThat(
            isPrefix(
                new byte[] {(byte) 0x01, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee},
                ciphertext))
        .isTrue();

    // Also check that aead is compatible with an Aead created with KmsEnvelopeAead.create(), if
    // the 5 byte prefix is removed.
    Aead keyEncryptionAead = new FakeKmsClient().getAead(kekUri);
    Aead aead2 = KmsEnvelopeAead.create(PredefinedAeadParameters.AES128_EAX, keyEncryptionAead);
    byte[] ciphertextWithoutPrefix = Arrays.copyOfRange(ciphertext, 5, ciphertext.length);
    byte[] decrypted = aead2.decrypt(ciphertextWithoutPrefix, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void getPrimitiveFromLegacyKmsEnvelopeAeadKey_wrongUriFails() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("wrong uri")
            .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_EAX)
            .setDekParametersForNewKeys(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .build();
    LegacyKmsEnvelopeAeadKey key = LegacyKmsEnvelopeAeadKey.create(parameters);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();

    assertThrows(GeneralSecurityException.class, () -> keysetHandle.getPrimitive(Aead.class));
  }

  @Test
  public void getPrimitive_parsingInvalidCiphetexts() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    LegacyKmsEnvelopeAeadKey key =
        LegacyKmsEnvelopeAeadKey.create(
            LegacyKmsEnvelopeAeadParameters.builder()
                .setKekUri(kekUri)
                .setDekParsingStrategy(DekParsingStrategy.ASSUME_AES_CTR_HMAC)
                .setDekParametersForNewKeys(
                    AesCtrHmacAeadParameters.builder()
                        .setAesKeySizeBytes(16)
                        .setHmacKeySizeBytes(32)
                        .setTagSizeBytes(16)
                        .setIvSizeBytes(16)
                        .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                        .build())
                .build());
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();
    Aead aead = keysetHandle.getPrimitive(Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    byte[] ciphertext = aead.encrypt(plaintext, aad);
    ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
    int encryptedDekSize = buffer.getInt();
    byte[] encryptedDek = new byte[encryptedDekSize];
    buffer.get(encryptedDek, 0, encryptedDekSize);
    byte[] payload = new byte[buffer.remaining()];
    buffer.get(payload, 0, buffer.remaining());

    // valid, should work
    byte[] ciphertext2 = ByteBuffer.allocate(ciphertext.length)
        .putInt(encryptedDekSize)
        .put(encryptedDek)
        .put(payload)
        .array();
    assertArrayEquals(plaintext, aead.decrypt(ciphertext2, aad));

    // negative length
    byte[] ciphertext3 =
        ByteBuffer.allocate(ciphertext.length)
            .putInt(-1)
            .put(encryptedDek)
            .put(payload)
            .array();
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext3, aad));

    // length larger than actual value
    byte[] ciphertext4 =
        ByteBuffer.allocate(ciphertext.length)
            .putInt(encryptedDek.length + 1)
            .put(encryptedDek)
            .put(payload)
            .array();
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext4, aad));

    // length larger than total ciphertext length
    byte[] ciphertext5 =
        ByteBuffer.allocate(ciphertext.length)
            .putInt(encryptedDek.length + payload.length + 1)
            .put(encryptedDek)
            .put(payload)
            .array();
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext5, aad));
  }

  @Test
  public void createKeyTemplate() throws Exception {
    // Intentionally using "weird" or invalid values for parameters,
    // to test that the function correctly puts them in the resulting template.
    String kekUri = "some example KEK URI";
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();
    com.google.crypto.tink.proto.KeyTemplate dekTemplateProto =
        KeyTemplateProtoConverter.toProto(dekTemplate);

    KeyTemplate template = KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate);

    com.google.crypto.tink.proto.KeyTemplate protoTemplate =
        KeyTemplateProtoConverter.toProto(template);
    assertThat(KmsEnvelopeAeadKeyManager.getKeyType()).isEqualTo(protoTemplate.getTypeUrl());
    assertThat(com.google.crypto.tink.proto.OutputPrefixType.RAW)
        .isEqualTo(protoTemplate.getOutputPrefixType());

    KmsEnvelopeAeadKeyFormat format =
        KmsEnvelopeAeadKeyFormat.parseFrom(
            protoTemplate.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(kekUri).isEqualTo(format.getKekUri());
    assertThat(dekTemplateProto.getTypeUrl()).isEqualTo(format.getDekTemplate().getTypeUrl());
    assertThat(dekTemplateProto.getValue()).isEqualTo(format.getDekTemplate().getValue());
  }

  @Test
  public void createKeyTemplate_ignoresOutputPrefix() throws Exception {
    // When we create LegacyKmsEnvelopeAeadParameters, the underlying OutputPrefixType in the
    // passed in dek Template is ignored.
    KeyTemplate template1 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "some URI", KeyTemplates.get("AES128_CTR_HMAC_SHA256"));
    KeyTemplate template2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "some URI", KeyTemplates.get("AES128_CTR_HMAC_SHA256_RAW"));
    assertThat(template1.toParameters()).isEqualTo(template2.toParameters());
  }

  @Test
  public void createKeyTemplate_aesGcm_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeMatchingKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM)
            .setDekParametersForNewKeys(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    // Check with both NO_PREFIX as well as TINK to ensure the Variant is ignored.
    KeyTemplate template1 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeMatchingKekUri", KeyTemplates.get("AES128_GCM"));
    assertThat(template1.toParameters()).isEqualTo(parameters);

    KeyTemplate template2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeMatchingKekUri", KeyTemplates.get("AES128_GCM_RAW"));
    assertThat(template2.toParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKeyTemplate_chacha_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeMatchingKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_CHACHA20POLY1305)
            .setDekParametersForNewKeys(
                ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX))
            .build();

    // Check with both NO_PREFIX as well as TINK to ensure the Variant is ignored.
    KeyTemplate template1 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeMatchingKekUri",
            KeyTemplate.createFrom(
                ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX)));
    assertThat(template1.toParameters()).isEqualTo(parameters);

    KeyTemplate template2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeMatchingKekUri",
            KeyTemplate.createFrom(
                ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK)));
    assertThat(template2.toParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKeyTemplate_xchacha_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeMatchingKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305)
            .setDekParametersForNewKeys(
                XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX))
            .build();

    // Check with both NO_PREFIX as well as TINK to ensure the Variant is ignored.
    KeyTemplate template1 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeMatchingKekUri",
            KeyTemplate.createFrom(
                XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX)));
    assertThat(template1.toParameters()).isEqualTo(parameters);

    KeyTemplate template2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeMatchingKekUri",
            KeyTemplate.createFrom(
                XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK)));
    assertThat(template2.toParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKeyTemplate_eax_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeOtherKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX)
            .setDekParametersForNewKeys(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    // Check with both NO_PREFIX as well as TINK to ensure the Variant is ignored.
    KeyTemplate template1 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeOtherKekUri", KeyTemplates.get("AES128_EAX_RAW"));
    assertThat(template1.toParameters()).isEqualTo(parameters);

    KeyTemplate template2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeOtherKekUri", KeyTemplates.get("AES128_EAX"));
    assertThat(template2.toParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKeyTemplate_gcmsiv_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeOtherKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM_SIV)
            .setDekParametersForNewKeys(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    // Check with both NO_PREFIX as well as TINK to ensure the Variant is ignored.
    KeyTemplate template1 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeOtherKekUri",
            KeyTemplate.createFrom(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build()));
    assertThat(template1.toParameters()).isEqualTo(parameters);

    KeyTemplate template2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeOtherKekUri",
            KeyTemplate.createFrom(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.TINK)
                    .build()));
    assertThat(template2.toParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKeyTemplate_aesctrhmac_works() throws Exception {
    LegacyKmsEnvelopeAeadParameters parameters =
        LegacyKmsEnvelopeAeadParameters.builder()
            .setKekUri("SomeOtherKekUri")
            .setDekParsingStrategy(
                LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_CTR_HMAC)
            .setDekParametersForNewKeys(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(16)
                    .setHmacKeySizeBytes(32)
                    .setTagSizeBytes(32)
                    .setIvSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                    .build())
            .build();

    // Check with both NO_PREFIX as well as TINK to ensure the Variant is ignored.
    KeyTemplate template1 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeOtherKekUri",
            KeyTemplate.createFrom(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(16)
                    .setHmacKeySizeBytes(32)
                    .setTagSizeBytes(32)
                    .setIvSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
                    .build()));
    assertThat(template1.toParameters()).isEqualTo(parameters);

    KeyTemplate template2 =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            "SomeOtherKekUri",
            KeyTemplate.createFrom(
                AesCtrHmacAeadParameters.builder()
                    .setAesKeySizeBytes(16)
                    .setHmacKeySizeBytes(32)
                    .setTagSizeBytes(32)
                    .setIvSizeBytes(16)
                    .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
                    .setVariant(AesCtrHmacAeadParameters.Variant.TINK)
                    .build()));
    assertThat(template2.toParameters()).isEqualTo(parameters);
  }

  @Test
  public void createKeyTemplateGenerateNewGetPrimitive_isSameAs_create() throws Exception {
    @Nullable Integer apiLevel = Util.getAndroidApiLevel();
    Assume.assumeTrue(apiLevel == null || apiLevel >= 30); // Run the test on java and android >= 30

    String keyUri = FakeKmsClient.createFakeKeyUri();

    // Create Aead primitive using createKeyTemplate, generateNew, and getPrimitive.
    // This requires that a KmsClient that supports keyUri is registered.
    KeyTemplate template =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(keyUri, KeyTemplates.get("AES128_GCM"));
    KeysetHandle keysetHandle = KeysetHandle.generateNew(template);
    Aead aead1 = keysetHandle.getPrimitive(Aead.class);

    // Create Aead using FakeKmsClient.getAead and KmsEnvelopeAead.create.
    // No KmsClient needs to be registered.
    Aead keyEncryptionAead = new FakeKmsClient().getAead(keyUri);
    Aead aead2 = KmsEnvelopeAead.create(PredefinedAeadParameters.AES256_GCM, keyEncryptionAead);

    // Test that aead1 and aead2 are the same.
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);
    byte[] ciphertext = aead1.encrypt(plaintext, associatedData);
    byte[] decrypted = aead2.decrypt(ciphertext, associatedData);
    assertThat(decrypted).isEqualTo(plaintext);
  }

  @Test
  public void multipleAeadsWithSameKekAndSameDekTemplate_canDecryptEachOther() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();

    KeysetHandle handle1 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate));
    Aead aead1 = handle1.getPrimitive(Aead.class);

    KeysetHandle handle2 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate));
    Aead aead2 = handle2.getPrimitive(Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    assertThat(aead1.decrypt(aead2.encrypt(plaintext, associatedData), associatedData))
        .isEqualTo(plaintext);
  }

  @Test
  public void keysetsWithTwoKmsEnvelopeAeadKeys_canDecryptWithBoth() throws Exception {
    KeyTemplate dekTemplate = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();
    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    String kekUri1 = FakeKmsClient.createFakeKeyUri();
    KeysetHandle handle1 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri1, dekTemplate));
    Aead aead1 = handle1.getPrimitive(Aead.class);
    byte[] ciphertext1 = aead1.encrypt(plaintext, associatedData);

    String kekUri2 = FakeKmsClient.createFakeKeyUri();
    KeysetHandle handle2 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri2, dekTemplate));
    Aead aead2 = handle2.getPrimitive(Aead.class);
    byte[] ciphertext2 = aead2.encrypt(plaintext, associatedData);

    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(handle1.getAt(0).getKey()).withRandomId().makePrimary())
            .addEntry(KeysetHandle.importKey(handle2.getAt(0).getKey()).withRandomId())
            .build();
    Aead aead = handle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(ciphertext1, associatedData)).isEqualTo(plaintext);
    assertThat(aead.decrypt(ciphertext2, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void multipleAeadsWithSameKekAndDifferentDekTemplateOfSameKeyType_canDecryptEachOther()
      throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();

    KeyTemplate dek1Template = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();
    KeysetHandle handle1 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dek1Template));
    Aead aead1 = handle1.getPrimitive(Aead.class);

    KeyTemplate dek2Template = AesCtrHmacAeadKeyManager.aes256CtrHmacSha256Template();
    KeysetHandle handle2 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dek2Template));
    Aead aead2 = handle2.getPrimitive(Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    byte[] ciphertext = aead1.encrypt(plaintext, associatedData);

    // This works because ciphertext contains an encrypted AesCtrHmacAeadKey, which aead2 correctly
    // decrypts and parses. The resulting key can then decrypt the ciphertext.
    assertThat(aead2.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  }

  @Test
  public void multipleAeadsWithSameKekAndDifferentDekTemplateKeyType_cannotDecryptEachOther()
      throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();

    KeyTemplate dek1Template = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();
    KeysetHandle handle1 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dek1Template));
    Aead aead1 = handle1.getPrimitive(Aead.class);

    KeyTemplate dek2Template = AesGcmKeyManager.aes128GcmTemplate();
    KeysetHandle handle2 =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dek2Template));
    Aead aead2 = handle2.getPrimitive(Aead.class);

    byte[] plaintext = Random.randBytes(20);
    byte[] associatedData = Random.randBytes(20);

    byte[] ciphertext = aead1.encrypt(plaintext, associatedData);

    // ciphertext contains an encrypted AesCtrHmacAeadKey proto. aead2 can decrypt it, but it
    // tries to parse it as an AesGcmKey proto. Either the parsing fails or the resulting key is
    // not able to decrypt the ciphertext.
    assertThrows(GeneralSecurityException.class, () -> aead2.decrypt(ciphertext, associatedData));
  }

  @Test
  public void createKeyTemplateWithEnvelopeKeyTemplateAsDekTemplate_fails() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();

    KeyTemplate dekTemplate =
        KmsEnvelopeAeadKeyManager.createKeyTemplate(
            kekUri, AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template());
    assertThrows(
        IllegalArgumentException.class,
        () -> KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dekTemplate));
  }

  @Test
  public void testSerializeAndParse_works() throws Exception {
    String kekUri = FakeKmsClient.createFakeKeyUri();
    KeyTemplate dek1Template = AesCtrHmacAeadKeyManager.aes128CtrHmacSha256Template();
    KeysetHandle handle =
        KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(kekUri, dek1Template));
    byte[] serialized = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle);
    KeysetHandle parsed = TinkProtoKeysetFormat.parseKeysetWithoutSecret(serialized);

    assertTrue(handle.equalsKeyset(parsed));
  }
}
