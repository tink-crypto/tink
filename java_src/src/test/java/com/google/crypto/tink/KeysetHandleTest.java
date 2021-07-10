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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.KeyStatusTypeProtoConverter;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.KeyData;
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
import com.google.crypto.tink.tinkkey.SecretKeyAccess;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeysetHandle. */
@RunWith(JUnit4.class)
public class KeysetHandleTest {

  @Rule public final Expect expect = Expect.create();

  private static interface EncryptOnly {
    byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException;
  }

  private static class AeadToEncryptOnlyWrapper implements PrimitiveWrapper<Aead, EncryptOnly> {
    @Override
    public EncryptOnly wrap(PrimitiveSet<Aead> set) throws GeneralSecurityException {
      return new EncryptOnly() {
        @Override
        public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
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
  public void getKeys() throws Exception {
    KeyTemplate keyTemplate = KeyTemplates.get("AES128_EAX");
    KeysetManager keysetManager = KeysetManager.withEmptyKeyset();
    final int numKeys = 3;
    for (int i = 0; i < numKeys; i++) {
      keysetManager.add(keyTemplate);
    }
    KeysetHandle handle = keysetManager.getKeysetHandle();
    Keyset keyset = handle.getKeyset();

    List<KeyHandle> keysetKeys = handle.getKeys();

    expect.that(keysetKeys).hasSize(numKeys);
    Map<Integer, KeyHandle> keysetKeysMap =
        keysetKeys.stream().collect(Collectors.toMap(KeyHandle::getId, key -> key));
    for (Keyset.Key key : keyset.getKeyList()) {
      expect.that(keysetKeysMap).containsKey(key.getKeyId());
      KeyHandle keysetKey = keysetKeysMap.get(key.getKeyId());
      expect
          .that(KeyStatusTypeProtoConverter.toProto(keysetKey.getStatus()))
          .isEqualTo(key.getStatus());
      KeyData keyData =
          ((ProtoKey) keysetKey.getKey(SecretKeyAccess.insecureSecretAccess())).getProtoKey();
      expect.that(keyData).isEqualTo(key.getKeyData());
    }
  }

  @Test
  public void generateNew_shouldWork() throws Exception {
    KeyTemplate template = AesEaxKeyManager.aes128EaxTemplate();

    KeysetHandle handle = KeysetHandle.generateNew(template);

    Keyset keyset = handle.getKeyset();
    expect.that(keyset.getKeyCount()).isEqualTo(1);
    Keyset.Key key = keyset.getKey(0);
    expect.that(keyset.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    expect.that(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    expect.that(key.hasKeyData()).isTrue();
    expect.that(key.getKeyData().getTypeUrl()).isEqualTo(template.getTypeUrl());
    AesEaxKeyFormat aesEaxKeyFormat =
        AesEaxKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesEaxKey aesEaxKey =
        AesEaxKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesEaxKey.getKeyValue().size()).isEqualTo(aesEaxKeyFormat.getKeySize());
  }

  @Test
  public void generateNew_withProtoKeyTemplate_shouldWork() throws Exception {
    com.google.crypto.tink.proto.KeyTemplate template =
        AesEaxKeyManager.aes128EaxTemplate().getProto();

    @SuppressWarnings("deprecation") // Need to test the deprecated function
    KeysetHandle handle = KeysetHandle.generateNew(template);

    Keyset keyset = handle.getKeyset();
    expect.that(keyset.getKeyCount()).isEqualTo(1);
    Keyset.Key key = keyset.getKey(0);
    expect.that(keyset.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    expect.that(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    expect.that(key.hasKeyData()).isTrue();
    expect.that(key.getKeyData().getTypeUrl()).isEqualTo(template.getTypeUrl());
    AesEaxKeyFormat aesEaxKeyFormat =
        AesEaxKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesEaxKey aesEaxKey =
        AesEaxKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesEaxKey.getKeyValue().size()).isEqualTo(aesEaxKeyFormat.getKeySize());
  }

  @Test
  public void generateNew_generatesDifferentKeys() throws Exception {
    KeyTemplate template = AesEaxKeyManager.aes128EaxTemplate();
    Set<String> keys = new TreeSet<>();

    int numKeys = 2;
    for (int j = 0; j < numKeys; j++) {
      KeysetHandle handle = KeysetHandle.generateNew(template);
      AesEaxKey aesEaxKey =
          AesEaxKey.parseFrom(
              handle.getKeyset().getKey(0).getKeyData().getValue(),
              ExtensionRegistryLite.getEmptyRegistry());
      keys.add(aesEaxKey.getKeyValue().toStringUtf8());
    }

    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createFromKey_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX");
    KeyHandle keyHandle = KeyHandle.generateNew(template);
    KeyAccess token = SecretKeyAccess.insecureSecretAccess();

    KeysetHandle handle = KeysetHandle.createFromKey(keyHandle, token);

    Keyset keyset = handle.getKeyset();
    expect.that(keyset.getKeyCount()).isEqualTo(1);
    Keyset.Key key = keyset.getKey(0);
    expect.that(keyset.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    expect.that(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.TINK);
    expect.that(key.hasKeyData()).isTrue();
    expect.that(key.getKeyData().getTypeUrl()).isEqualTo(template.getTypeUrl());
    AesEaxKeyFormat aesEaxKeyFormat =
        AesEaxKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    AesEaxKey aesEaxKey =
        AesEaxKey.parseFrom(key.getKeyData().getValue(), ExtensionRegistryLite.getEmptyRegistry());
    expect.that(aesEaxKey.getKeyValue().size()).isEqualTo(aesEaxKeyFormat.getKeySize());
  }

  @Test
  public void toString_containsNoKeyMaterial() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);

    String keysetInfo = handle.toString();

    expect.that(keysetInfo).doesNotContain(keyValue);
    expect.that(handle.getKeyset().toString()).contains(keyValue);
  }

  @Test
  public void writeThenRead_returnsSameKeyset() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(HmacKeyManager.hmacSha256Template());
    Aead masterKey =
        Registry.getPrimitive(
            Registry.newKeyData(AesEaxKeyManager.aes128EaxTemplate()), Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    handle.write(writer, masterKey);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    KeysetHandle handle2 = KeysetHandle.read(reader, masterKey);

    assertThat(handle.getKeyset()).isEqualTo(handle2.getKeyset());
  }

  @Test
  public void getPublicKeysetHandle_shouldWork() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
    KeyData privateKeyData = privateHandle.getKeyset().getKey(0).getKeyData();
    EcdsaPrivateKey privateKey =
        EcdsaPrivateKey.parseFrom(
            privateKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());

    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();

    expect.that(publicHandle.getKeyset().getKeyCount()).isEqualTo(1);
    expect
        .that(privateHandle.getKeyset().getPrimaryKeyId())
        .isEqualTo(publicHandle.getKeyset().getPrimaryKeyId());
    KeyData publicKeyData = publicHandle.getKeyset().getKey(0).getKeyData();
    expect.that(publicKeyData.getTypeUrl()).isEqualTo(SignatureConfig.ECDSA_PUBLIC_KEY_TYPE_URL);
    expect
        .that(publicKeyData.getKeyMaterialType())
        .isEqualTo(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
    expect
        .that(publicKeyData.getValue().toByteArray())
        .isEqualTo(privateKey.getPublicKey().toByteArray());
    PublicKeySign signer = PublicKeySignFactory.getPrimitive(privateHandle);
    PublicKeyVerify verifier = PublicKeyVerifyFactory.getPrimitive(publicHandle);
    byte[] message = Random.randBytes(20);
    verifier.verify(signer.sign(message), message);
  }

  /** Tests that when encryption failed an exception is thrown. */
  @Test
  public void write_withFaultyAead_shouldThrow() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(HmacKeyManager.hmacSha256Template());
    TestUtil.DummyAead faultyAead = new TestUtil.DummyAead();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    assertThrows(GeneralSecurityException.class, () -> handle.write(writer, faultyAead));
  }

  @Test
  public void read_withNoMasterKeyInput_shouldThrow() throws Exception {
    KeysetReader reader = BinaryKeysetReader.withBytes(new byte[0]);

    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.read(reader, null /* masterKey */));
  }

  @Test
  public void getPrimitive_shouldWork() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(AesEaxKeyManager.aes128EaxTemplate());
    byte[] message = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);

    Aead aead = handle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(aead.encrypt(message, aad), aad)).isEqualTo(message);
  }

  // Tests that getPrimitive does correct wrapping and not just return the primary. For this, we
  // simply add a raw, non-primary key and encrypt directly with it.
  @Test
  public void getPrimitive_wrappingDoneCorrectly() throws Exception {
    KeyData rawKeyData = Registry.newKeyData(AesEaxKeyManager.aes128EaxTemplate());
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                Registry.newKeyData(AesEaxKeyManager.aes128EaxTemplate().getProto()),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK),
            TestUtil.createKey(rawKeyData, 43, KeyStatusType.ENABLED, OutputPrefixType.RAW));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    byte[] message = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);
    Aead aeadToEncrypt = Registry.getPrimitive(rawKeyData, Aead.class);

    Aead aead = handle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(aeadToEncrypt.encrypt(message, aad), aad)).isEqualTo(message);
  }

  @Test
  public void getPrimitive_differentPrimitive_shouldWork() throws Exception {
    // We use RAW because the EncryptOnly wrapper wraps everything RAW.
    KeysetHandle handle = KeysetHandle.generateNew(AesEaxKeyManager.rawAes128EaxTemplate());
    byte[] message = Random.randBytes(20);

    EncryptOnly encryptOnly = handle.getPrimitive(EncryptOnly.class);

    Aead aead = handle.getPrimitive(Aead.class);
    assertThat(aead.decrypt(encryptOnly.encrypt(message), new byte[0])).isEqualTo(message);
  }

  @Test
  public void readNoSecret_shouldWork() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
    Keyset keyset = privateHandle.getPublicKeysetHandle().getKeyset();

    Keyset keyset2 = KeysetHandle.readNoSecret(keyset.toByteArray()).getKeyset();
    Keyset keyset3 =
        KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray())).getKeyset();

    expect.that(keyset).isEqualTo(keyset2);
    expect.that(keyset).isEqualTo(keyset3);
  }

  @Test
  public void readNoSecret_withTypeSymmetric_shouldThrow() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));

    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(keyset.toByteArray()));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray())));
  }

  @Test
  public void readNoSecret_withTypeAsymmetricPrivate_shouldThrow() throws Exception {
    Keyset keyset = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256).getKeyset();

    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(keyset.toByteArray()));
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(keyset.toByteArray())));
  }

  @Test
  public void readNoSecret_withEmptyKeyset_shouldThrow() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(new byte[0]));
  }

  @Test
  public void readNoSecret_withInvalidKeyset_shouldThrow() throws Exception {
    byte[] proto = new byte[] {0x00, 0x01, 0x02};
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(proto));
  }

  @Test
  public void writeNoSecretThenReadNoSecret_returnsSameKeyset() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
    KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    Keyset keyset = publicHandle.getKeyset();

    publicHandle.writeNoSecret(writer);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    Keyset keyset2 = KeysetHandle.readNoSecret(reader).getKeyset();

    assertThat(keyset).isEqualTo(keyset2);
  }

  @Test
  public void writeNoSecret_withTypeSymmetric_shouldThrow() throws Exception {
    String keyValue = "01234567890123456";
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);

    assertThrows(GeneralSecurityException.class, () -> handle.writeNoSecret(/* writer= */ null));
  }

  @Test
  public void writeNoSecret_withTypeAsymmetricPrivate_shouldThrow() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);

    assertThrows(GeneralSecurityException.class, () -> handle.writeNoSecret(null /* writer */));
  }

  @Test
  public void primaryKey_shouldWork() throws Exception {
    KeyTemplate kt1 = AesEaxKeyManager.aes128EaxTemplate();
    KeyTemplate kt2 = HmacKeyManager.hmacSha256Template();
    KeysetHandle ksh =
        KeysetManager.withKeysetHandle(KeysetHandle.generateNew(kt1)).add(kt2).getKeysetHandle();

    KeyHandle kh = ksh.primaryKey();

    ProtoKey pk = (ProtoKey) kh.getKey(SecretKeyAccess.insecureSecretAccess());
    assertThat(pk.getProtoKey().getTypeUrl()).isEqualTo(kt1.getTypeUrl());
  }

  @Test
  public void primaryKey_noPrimaryPresent_shouldThrow() throws Exception {
    KeyTemplate kt1 = AesEaxKeyManager.aes128EaxTemplate();
    KeyTemplate kt2 = HmacKeyManager.hmacSha256Template();
    KeysetHandle ksh = KeysetManager.withEmptyKeyset().add(kt1).add(kt2).getKeysetHandle();

    assertThrows(GeneralSecurityException.class, ksh::primaryKey);
  }
}
