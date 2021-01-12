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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.PublicKeySignFactory;
import com.google.crypto.tink.signature.PublicKeyVerifyFactory;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignatureKeyTemplates;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.ProtoKey;
import com.google.crypto.tink.tinkkey.SecretKeyAccess;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeysetHandle. */
@RunWith(JUnit4.class)
public class KeysetHandleTest {
  /**
   * A KeyTypeManager for testing. It accepts AesGcmKeys and produces primitives as with the passed
   * in factory.
   */
  public static class TestKeyTypeManager extends KeyTypeManager<AesGcmKey> {
    public TestKeyTypeManager(PrimitiveFactory<?, AesGcmKey>... factories) {
      super(AesGcmKey.class, factories);
    }

    @Override
    public String getKeyType() {
      return "type.googleapis.com/google.crypto.tink.AesGcmKey";
    }

    @Override
    public int getVersion() {
      return 1;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.SYMMETRIC;
    }

    @Override
    public void validateKey(AesGcmKey keyProto) {}

    @Override
    public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return AesGcmKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }
  }

  private static interface EncryptOnly {
    byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException;
  }

  private static class AeadToEncryptOnlyWrapper implements PrimitiveWrapper<Aead, EncryptOnly> {
    @Override
    public EncryptOnly wrap(PrimitiveSet<Aead> set) throws GeneralSecurityException {
      return new EncryptOnly() {
        @Override
        public byte[] encrypt(final byte[] plaintext)
            throws GeneralSecurityException {
          return set.getPrimary().getPrimitive().encrypt(plaintext, new byte[0]);
        }
      };
    }

    @Override
    public Class<EncryptOnly> getPrimitiveClass() {
      return EncryptOnly.class;
    }

    @Override
    public Class<Aead> getInputPrimitiveClass() {
      return Aead.class;
    }
  }

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    Config.register(TinkConfig.TINK_1_0_0);
    Registry.registerPrimitiveWrapper(new AeadToEncryptOnlyWrapper());
  }

  @Test
  public void testGenerateNew() throws Exception {
    KeyTemplate kt = AesGcmKeyManager.aes128GcmTemplate();
    KeysetHandle handle = KeysetHandle.generateNew(kt);
    Keyset keyset = handle.getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);

    Keyset.Key key = keyset.getKey(0);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(key.hasKeyData()).isTrue();
    assertThat(key.getKeyData().getTypeUrl()).isEqualTo(kt.getTypeUrl());

    AesGcmKeyFormat aesGcmKeyFormat =
        AesGcmKeyFormat.parseFrom(kt.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(aesGcmKey.getKeyValue().size()).isEqualTo(aesGcmKeyFormat.getKeySize());
  }

  @Test
  public void testGenerateNew_proto() throws Exception {
    com.google.crypto.tink.proto.KeyTemplate kt = AeadKeyTemplates.AES128_EAX;
    KeysetHandle handle = KeysetHandle.generateNew(kt);
    Keyset keyset = handle.getKeyset();

    assertThat(keyset.getKeyCount()).isEqualTo(1);

    Keyset.Key key = keyset.getKey(0);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(key.hasKeyData()).isTrue();
    assertThat(key.getKeyData().getTypeUrl()).isEqualTo(kt.getTypeUrl());

    AesGcmKeyFormat aesGcmKeyFormat =
        AesGcmKeyFormat.parseFrom(kt.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(aesGcmKey.getKeyValue().size()).isEqualTo(aesGcmKeyFormat.getKeySize());
  }

  @Test
  public void testGenerateNew_multipleTimes() throws Exception {
    KeyTemplate kt = AesGcmKeyManager.aes128GcmTemplate();

    // Makes sure that the key generation is randomized.
    Set<String> keys = new TreeSet<>();
    for (int j = 0; j < 8; j++) {
      KeysetHandle handle = KeysetHandle.generateNew(kt);
      AesGcmKey aesGcmKey =
          AesGcmKey.parseFrom(
              handle.getKeyset().getKey(0).getKeyData().getValue(),
              ExtensionRegistryLite.getEmptyRegistry());
      keys.add(aesGcmKey.getKeyValue().toStringUtf8());
    }
    assertThat(keys).hasSize(8);
  }

  @Test
  public void testGenerateNew_multipleTimes_proto() throws Exception {
    com.google.crypto.tink.proto.KeyTemplate kt = AeadKeyTemplates.AES128_EAX;

    // Makes sure that the key generation is randomized.
    Set<String> keys = new TreeSet<>();
    for (int j = 0; j < 8; j++) {
      KeysetHandle handle = KeysetHandle.generateNew(kt);
      AesGcmKey aesGcmKey =
          AesGcmKey.parseFrom(
              handle.getKeyset().getKey(0).getKeyData().getValue(),
              ExtensionRegistryLite.getEmptyRegistry());
      keys.add(aesGcmKey.getKeyValue().toStringUtf8());
    }
    assertThat(keys).hasSize(8);
  }

  @Test
  public void createFromKey() throws Exception {
    KeyTemplate kt = AesGcmKeyManager.aes128GcmTemplate();
    KeyHandle kh = KeyHandle.createFromKey(Registry.newKeyData(kt), kt.getOutputPrefixType());
    KeyAccess ka = SecretKeyAccess.insecureSecretAccess();

    KeysetHandle handle = KeysetHandle.createFromKey(kh, ka);

    Keyset keyset = handle.getKeyset();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    Keyset.Key key = keyset.getKey(0);
    assertThat(keyset.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    assertThat(key.hasKeyData()).isTrue();
    assertThat(key.getKeyData().getTypeUrl()).isEqualTo(kt.getTypeUrl());
    AesGcmKeyFormat aesGcmKeyFormat =
        AesGcmKeyFormat.parseFrom(kt.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesGcmKey aesGcmKey =
        AesGcmKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(aesGcmKey.getKeyValue().size()).isEqualTo(aesGcmKeyFormat.getKeySize());
  }

  /** Tests that toString doesn't contain key material. */
  @Test
  public void testToString() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertEquals(keyset, handle.getKeyset());

    String keysetInfo = handle.toString();
    assertFalse(keysetInfo.contains(keyValue));
    assertTrue(handle.getKeyset().toString().contains(keyValue));
  }

  @Test
  public void testWriteEncrypted() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    // Encrypt the keyset with an AeadKey.
    com.google.crypto.tink.proto.KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_EAX;
    Aead masterKey = Registry.getPrimitive(Registry.newKeyData(masterKeyTemplate));
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    handle.write(writer, masterKey);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    KeysetHandle handle2 = KeysetHandle.read(reader, masterKey);
    assertEquals(handle.getKeyset(), handle2.getKeyset());
  }

  /** Tests a public keyset is extracted properly from a private keyset. */
  @Test
  public void testGetPublicKeysetHandle() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
    KeyData privateKeyData = privateHandle.getKeyset().getKey(0).getKeyData();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.parseFrom(
            privateKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    assertEquals(1, publicHandle.getKeyset().getKeyCount());
    assertEquals(
        privateHandle.getKeyset().getPrimaryKeyId(), publicHandle.getKeyset().getPrimaryKeyId());
    KeyData publicKeyData = publicHandle.getKeyset().getKey(0).getKeyData();
    assertEquals(SignatureConfig.ECDSA_PUBLIC_KEY_TYPE_URL, publicKeyData.getTypeUrl());
    assertEquals(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC, publicKeyData.getKeyMaterialType());
    assertArrayEquals(
        privateKey.getPublicKey().toByteArray(), publicKeyData.getValue().toByteArray());

    PublicKeySign signer = PublicKeySignFactory.getPrimitive(privateHandle);
    PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(publicHandle);
    byte[] message = Random.randBytes(20);
    try {
      verifier.verify(signer.sign(message), message);
    } catch (GeneralSecurityException e) {
      fail("Should not fail: " + e);
    }
  }

  /** Tests that when encryption failed an exception is thrown. */
  @Test
  public void testEncryptFailed() throws Exception {
    KeysetHandle handle =
        KeysetManager.withEmptyKeyset()
            .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
            .getKeysetHandle();
    // Encrypt with dummy Aead.
    TestUtil.DummyAead faultyAead = new TestUtil.DummyAead();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    try {
      handle.write(writer, faultyAead);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "dummy");
    }
  }

  @Test
  public void testVoidInputs() throws Exception {
    KeysetHandle unused;
    try {
      KeysetReader reader = BinaryKeysetReader.withBytes(new byte[0]);
      unused = KeysetHandle.read(reader, null /* masterKey */);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }
  }

  @Test
  public void testGetPrimitive_basic() throws Exception {
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                Registry.newKeyData(AeadKeyTemplates.AES128_EAX),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    byte[] message = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    Aead aead = handle.getPrimitive(Aead.class);
    assertArrayEquals(aead.decrypt(aead.encrypt(message, aad), aad), message);
  }

  // Tests that getPrimitive does correct wrapping and not just return the primary. For this, we
  // simply add a raw, non-primary key and encrypt directly with it.
  @Test
  public void testGetPrimitive_wrappingDoneCorrectly() throws Exception {
    KeyData rawKeyData = Registry.newKeyData(AeadKeyTemplates.AES128_EAX);
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                Registry.newKeyData(AeadKeyTemplates.AES128_EAX),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(
                rawKeyData,
                43,
                KeyStatusType.ENABLED,
                OutputPrefixType.RAW));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    byte[] message = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    Aead aeadToEncrypt = Registry.getPrimitive(rawKeyData, Aead.class);
    Aead aead = handle.getPrimitive(Aead.class);
    assertArrayEquals(aead.decrypt(aeadToEncrypt.encrypt(message, aad), aad), message);
  }

  @Test
  public void testGetPrimitive_differentPrimitive_works() throws Exception {
    // We use RAW because the EncryptOnly wrapper wraps everything RAW.
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                Registry.newKeyData(AeadKeyTemplates.AES128_EAX),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.RAW));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    byte[] message = Random.randBytes(20);
    EncryptOnly encryptOnly = handle.getPrimitive(EncryptOnly.class);
    Aead aead = handle.getPrimitive(Aead.class);
    assertArrayEquals(aead.decrypt(encryptOnly.encrypt(message), new byte[0]), message);
  }

  @Test
  public void readNoSecretShouldWork() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
    Keyset keyset = privateHandle.getPublicKeysetHandle().getKeyset();
    Keyset keyset2 = KeysetHandle.readNoSecret(keyset.toByteArray()).getKeyset();
    Keyset keyset3 =
        KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray())).getKeyset();

    assertEquals(keyset, keyset2);
    assertEquals(keyset, keyset3);
  }

  @Test
  public void readNoSecretFailWithTypeSymmetric() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    try {
      KeysetHandle unused = KeysetHandle.readNoSecret(keyset.toByteArray());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains key material of type");
      assertExceptionContains(e, " type.googleapis.com/google.crypto.tink.HmacKey");
    }

    try {
      KeysetHandle unused =
          KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray()));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains key material");
    }
  }

  @Test
  public void readNoSecretFailWithTypeAsymmetricPrivate() throws Exception {
    Keyset keyset = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256).getKeyset();

    try {
      KeysetHandle unused = KeysetHandle.readNoSecret(keyset.toByteArray());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains key material");
    }

    try {
      KeysetHandle unused =
          KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray()));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains key material");
    }
  }

  @Test
  public void readNoSecretFailWithEmptyKeyset() throws Exception {
    try {
      KeysetHandle unused = KeysetHandle.readNoSecret(new byte[0]);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }
  }

  @Test
  public void readNoSecretFailWithInvalidKeyset() throws Exception {
    byte[] proto = new byte[] {0x00, 0x01, 0x02};
    try {
      KeysetHandle unused = KeysetHandle.readNoSecret(proto);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "invalid");
    }
  }

  @Test
  public void writeNoSecretShouldWork() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    Keyset keyset = publicHandle.getKeyset();
    publicHandle.writeNoSecret(writer);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    Keyset keyset2 = KeysetHandle.readNoSecret(reader).getKeyset();
    assertEquals(keyset, keyset2);
  }

  @Test
  public void writeNoSecretFailWithTypeSymmetric() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    try {
      handle.writeNoSecret(null /* writer */);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains key material");
    }
  }

  @Test
  public void writeNoSecretFailWithTypeAsymmetricPrivate() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);

    try {
      handle.writeNoSecret(null /* writer */);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains key material");
    }
  }

  @Test
  public void findPrimaryKey_shouldWork() throws Exception {
    KeyTemplate kt1 = AesGcmKeyManager.aes128GcmTemplate();
    KeyTemplate kt2 = HmacKeyManager.hmacSha256Template();
    KeysetHandle ksh =
        KeysetManager.withKeysetHandle(KeysetHandle.generateNew(kt1)).add(kt2).getKeysetHandle();

    KeyHandle kh = ksh.primaryKey();

    ProtoKey pk = (ProtoKey) kh.getKey(SecretKeyAccess.insecureSecretAccess());
    assertThat(pk.getProtoKey().getTypeUrl()).isEqualTo(kt1.getTypeUrl());
  }

  @Test
  public void findPrimaryKey_noPrimary_shouldThrow() throws Exception {
    KeyTemplate kt1 = AesGcmKeyManager.aes128GcmTemplate();
    KeyTemplate kt2 = HmacKeyManager.hmacSha256Template();
    KeysetHandle ksh = KeysetManager.withEmptyKeyset().add(kt1).add(kt2).getKeysetHandle();

    assertThrows(GeneralSecurityException.class, ksh::primaryKey);
  }
}
