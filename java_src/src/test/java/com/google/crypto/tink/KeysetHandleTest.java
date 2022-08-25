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
import static org.junit.Assume.assumeFalse;

import com.google.common.truth.Expect;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeyStatusTypeProtoConverter;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.testing.FakeMonitoringClient;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.monitoring.MonitoringClient;
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
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.tinkkey.KeyAccess;
import com.google.crypto.tink.tinkkey.KeyHandle;
import com.google.crypto.tink.tinkkey.SecretKeyAccess;
import com.google.crypto.tink.tinkkey.internal.ProtoKey;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
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
    private static class EncryptOnlyWithMonitoring implements EncryptOnly {

      private final MonitoringClient.Logger logger;
      private final PrimitiveSet<Aead> primitiveSet;

      EncryptOnlyWithMonitoring(PrimitiveSet<Aead> primitiveSet) {
        this.primitiveSet = primitiveSet;
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        logger =
            client.createLogger(
                MonitoringUtil.getMonitoringKeysetInfo(primitiveSet), "encrypt_only", "encrypt");
      }

      @Override
      public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
        logger.log(primitiveSet.getPrimary().getKeyId(), plaintext.length);
        return primitiveSet.getPrimary().getPrimitive().encrypt(plaintext, new byte[0]);
      }
    }

    @Override
    public EncryptOnly wrap(PrimitiveSet<Aead> set) throws GeneralSecurityException {
      return new EncryptOnlyWithMonitoring(set);
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
    KeyTemplate template = KeyTemplates.get("AES128_EAX");

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
    com.google.crypto.tink.proto.KeyTemplate template = KeyTemplates.get("AES128_EAX").getProto();

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
    KeyTemplate template = KeyTemplates.get("AES128_EAX");
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
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_256BITTAG"));
    Aead masterKey =
        Registry.getPrimitive(Registry.newKeyData(KeyTemplates.get("AES128_EAX")), Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    handle.write(writer, masterKey);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    KeysetHandle handle2 = KeysetHandle.read(reader, masterKey);

    assertThat(handle.getKeyset()).isEqualTo(handle2.getKeyset());
  }

  @Test
  public void writeThenReadWithAssociatedData_returnsSameKeyset() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_256BITTAG"));
    Aead masterKey =
        Registry.getPrimitive(Registry.newKeyData(KeyTemplates.get("AES128_EAX")), Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    handle.writeWithAssociatedData(writer, masterKey, new byte[] {0x01, 0x02});
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    KeysetHandle handle2 =
        KeysetHandle.readWithAssociatedData(reader, masterKey, new byte[] {0x01, 0x02});

    assertThat(handle.getKeyset()).isEqualTo(handle2.getKeyset());
  }

  @Test
  public void writeThenReadWithDifferentAssociatedData_shouldThrow() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_256BITTAG"));
    Aead masterKey =
        Registry.getPrimitive(Registry.newKeyData(KeyTemplates.get("AES128_EAX")), Aead.class);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);

    handle.writeWithAssociatedData(writer, masterKey, new byte[] {0x01, 0x02});
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readWithAssociatedData(reader, masterKey, new byte[] {0x01, 0x03}));
  }

  /**
   * A test vector for readWithAssociatedData, generated with this implementation. It uses a
   * AES128_EAX template for the wrapping key, and a HMAC_SHA256_128BITTAG for the mac.
   */
  @Test
  public void readWithAssociatedDataTestVector() throws Exception {
    // An AEAD key, with which we encrypt the mac key below (using the encrypted keyset api).
    final byte[] serializedWrappingKeyset =
        Hex.decode(
            "08b891f5a20412580a4c0a30747970652e676f6f676c65617069732e636f6d2f676f6f676c652e6372797"
                + "0746f2e74696e6b2e4165734561784b65791216120208101a10e5d7d0cdd649e81e7952260689b2"
                + "e1971801100118b891f5a2042001");
    final byte[] associatedData = Hex.decode("abcdef330012");
    // A Mac key, encrypted with the above, using ASSOCIATED_DATA as aad.
    final byte[] encryptedSerializedKeyset =
        Hex.decode(
            "12950101445d48b8b5f591efaf73a46df9ebd7b6ac471cc0cf4f815a4f012fcaffc8f0b2b10b30c33194f"
                + "0b291614bd8e1d2e80118e5d6226b6c41551e104ef8cd8ee20f1c14c1b87f6eed5fb04a91feafaa"
                + "cbf6f368519f36f97f7d08b24c8e71b5e620c4f69615ef0479391666e2fb32e46b416893fc4e564"
                + "ba927b22ebff2a77bd3b5b8d5afa162cbd35c94c155cdfa13c8a9c964cde21a4208f5909ce90112"
                + "3a0a2e747970652e676f6f676c65617069732e636f6d2f676f6f676c652e63727970746f2e74696"
                + "e6b2e486d61634b6579100118f5909ce9012001");
    // A message whose tag we computed with the wrapped key.
    final byte[] message = Hex.decode("");
    final byte[] tag = Hex.decode("011d270875989dd6fbd5f54dbc9520bb41efd058d5");

    KeysetReader wrappingReader = BinaryKeysetReader.withBytes(serializedWrappingKeyset);
    Aead wrapperAead = CleartextKeysetHandle.read(wrappingReader).getPrimitive(Aead.class);

    KeysetReader encryptedReader = BinaryKeysetReader.withBytes(encryptedSerializedKeyset);
    Mac mac =
        KeysetHandle.readWithAssociatedData(encryptedReader, wrapperAead, associatedData)
            .getPrimitive(Mac.class);
    mac.verifyMac(tag, message);
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
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("HMAC_SHA256_256BITTAG"));
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
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES128_EAX"));
    byte[] message = Random.randBytes(20);
    byte[] aad = Random.randBytes(20);

    Aead aead = handle.getPrimitive(Aead.class);

    assertThat(aead.decrypt(aead.encrypt(message, aad), aad)).isEqualTo(message);
  }

  // Tests that getPrimitive does correct wrapping and not just return the primary. For this, we
  // simply add a raw, non-primary key and encrypt directly with it.
  @Test
  public void getPrimitive_wrappingDoneCorrectly() throws Exception {
    KeyData rawKeyData = Registry.newKeyData(KeyTemplates.get("AES128_EAX"));
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                Registry.newKeyData(KeyTemplates.get("AES128_EAX").getProto()),
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
  public void monitoringClientGetsAnnotationsWithKeysetInfo() throws Exception {
    MutableMonitoringRegistry.globalInstance().clear();
    FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
    MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);

    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createAesGcmKeyData(
                    TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f")),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    byte[] message = Random.randBytes(123);
    MonitoringAnnotations annotations =
        MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
    KeysetHandle handleWithAnnotations = KeysetHandle.fromKeysetAndAnnotations(keyset, annotations);
    EncryptOnly encryptOnlyWithAnnotations = handleWithAnnotations.getPrimitive(EncryptOnly.class);
    encryptOnlyWithAnnotations.encrypt(message);
    List<FakeMonitoringClient.LogEntry> entries = fakeMonitoringClient.getLogEntries();
    assertThat(entries).hasSize(1);
    assertThat(entries.get(0).getKeysetInfo().getAnnotations()).isEqualTo(annotations);
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
    KeyTemplate kt1 = KeyTemplates.get("AES128_EAX");
    KeyTemplate kt2 = KeyTemplates.get("HMAC_SHA256_256BITTAG");
    KeysetHandle ksh =
        KeysetManager.withKeysetHandle(KeysetHandle.generateNew(kt1)).add(kt2).getKeysetHandle();

    KeyHandle kh = ksh.primaryKey();

    ProtoKey pk = (ProtoKey) kh.getKey(SecretKeyAccess.insecureSecretAccess());
    assertThat(pk.getProtoKey().getTypeUrl()).isEqualTo(kt1.getTypeUrl());
  }

  @Test
  public void primaryKey_noPrimaryPresent_shouldThrow() throws Exception {
    KeyTemplate kt1 = KeyTemplates.get("AES128_EAX");
    KeyTemplate kt2 = KeyTemplates.get("HMAC_SHA256_256BITTAG");
    KeysetHandle ksh = KeysetManager.withEmptyKeyset().add(kt1).add(kt2).getKeysetHandle();

    assertThrows(GeneralSecurityException.class, ksh::primaryKey);
  }

  @Test
  public void testGetAt_singleKey_works() throws Exception {
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertThat(handle.size()).isEqualTo(1);
    KeysetHandle.Entry entry = handle.getAt(0);
    assertThat(entry.getId()).isEqualTo(42);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry.isPrimary()).isTrue();
    assertThat(entry.getKey().getClass()).isEqualTo(LegacyProtoKey.class);
  }

  @Test
  public void testGetAt_multipleKeys_works() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.DISABLED,
            OutputPrefixType.TINK);
    Keyset.Key key2 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("abcdefghijklmnopq".getBytes(UTF_8), 32),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.CRUNCHY);
    Keyset.Key key3 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("ABCDEFGHIJKLMNOPQ".getBytes(UTF_8), 32),
            46,
            KeyStatusType.DESTROYED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1, key2, key3);
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(44).build());

    assertThat(handle.size()).isEqualTo(3);
    assertThat(handle.getAt(0).getId()).isEqualTo(42);
    assertThat(handle.getAt(0).getStatus()).isEqualTo(KeyStatus.DISABLED);
    assertThat(handle.getAt(0).isPrimary()).isFalse();

    assertThat(handle.getAt(1).getId()).isEqualTo(44);
    assertThat(handle.getAt(1).getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(handle.getAt(1).isPrimary()).isTrue();

    assertThat(handle.getAt(2).getId()).isEqualTo(46);
    assertThat(handle.getAt(2).getStatus()).isEqualTo(KeyStatus.DESTROYED);
    assertThat(handle.getAt(2).isPrimary()).isFalse();
  }

  @Test
  public void testPrimary_multipleKeys_works() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Keyset.Key key2 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("abcdefghijklmnopq".getBytes(UTF_8), 32),
            44,
            KeyStatusType.ENABLED,
            OutputPrefixType.CRUNCHY);
    Keyset.Key key3 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("ABCDEFGHIJKLMNOPQ".getBytes(UTF_8), 32),
            46,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1, key2, key3);
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(44).build());
    KeysetHandle.Entry primary = handle.getPrimary();
    assertThat(primary.getId()).isEqualTo(44);
    assertThat(primary.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(primary.isPrimary()).isTrue();
  }

  @Test
  public void testGetPrimary_noPrimary_throws() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1);
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(77).build());

    assertThrows(IllegalStateException.class, handle::getPrimary);
  }

  @Test
  public void testGetPrimary_disabledPrimary_throws() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.DISABLED,
            OutputPrefixType.TINK);
    Keyset keyset = TestUtil.createKeyset(key1);
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(16).build());

    assertThrows(IllegalStateException.class, handle::getPrimary);
  }

  @Test
  public void testGetAt_indexOutOfBounds_throws() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.ENABLED,
            OutputPrefixType.TINK);
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(key1));

    assertThrows(IndexOutOfBoundsException.class, () -> handle.getAt(-1));
    assertThrows(IndexOutOfBoundsException.class, () -> handle.getAt(1));
  }

  @Test
  public void testGetAt_wrongStatus_throws() throws Exception {
    Keyset.Key key1 =
        TestUtil.createKey(
            TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
            42,
            KeyStatusType.UNKNOWN_STATUS,
            OutputPrefixType.TINK);
    KeysetHandle handle = KeysetHandle.fromKeyset(TestUtil.createKeyset(key1));

    assertThrows(IllegalStateException.class, () -> handle.getAt(0));
  }

  @Immutable
  private static final class TestKey extends Key {
    private final ByteString keymaterial;

    public TestKey(ByteString keymaterial) {
      this.keymaterial = keymaterial;
    }

    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    @Nullable
    public Integer getIdRequirementOrNull() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException("Not needed in test");
    }

    public ByteString getKeyMaterial() {
      return keymaterial;
    }
  }

  private static TestKey parseTestKey(
      ProtoKeySerialization serialization,
      @Nullable com.google.crypto.tink.SecretKeyAccess access) {
    return new TestKey(serialization.getValue());
  }

  /**
   * Tests that key parsing via the serialization registry works as expected.
   *
   * <p>NOTE: This adds a parser to the MutableSerializationRegistry, which no other test uses.
   */
  @Test
  public void testKeysAreParsed() throws Exception {
    ByteString value = ByteString.copyFromUtf8("some value");
    // NOTE: This adds a parser to the MutableSerializationRegistry, which no other test uses.
    MutableSerializationRegistry.globalInstance()
        .registerKeyParser(
            KeyParser.create(
                KeysetHandleTest::parseTestKey,
                Bytes.copyFrom("testKeyTypeUrl".getBytes(UTF_8)),
                ProtoKeySerialization.class));
    Keyset keyset =
        Keyset.newBuilder()
            .setPrimaryKeyId(1)
            .addKey(
                Keyset.Key.newBuilder()
                    .setKeyId(1)
                    .setStatus(KeyStatusType.ENABLED)
                    .setKeyData(KeyData.newBuilder().setTypeUrl("testKeyTypeUrl").setValue(value)))
            .build();
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertThat(((TestKey) handle.getPrimary().getKey()).getKeyMaterial()).isEqualTo(value);
  }

  @Test
  public void testBuilder_basic() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();

    assertThat(keysetHandle.size()).isEqualTo(1);
    assertThat(keysetHandle.getAt(0).getKey().getParameters())
        .isEqualTo(AesCmacParameters.create(/*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 16));
  }

  @Test
  public void testBuilder_multipleKeys() throws Exception {
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW")
                    .withRandomId()
                    .setStatus(KeyStatus.DISABLED))
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.createForKeyset(
                            /*keySizeBytes=*/ 32,
                            /*tagSizeBytes=*/ 10,
                            AesCmacParameters.Variant.CRUNCHY))
                    .withRandomId()
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.createForKeyset(
                            /*keySizeBytes=*/ 32,
                            /*tagSizeBytes=*/ 13,
                            AesCmacParameters.Variant.LEGACY))
                    .withRandomId())
            .build();
    assertThat(keysetHandle.size()).isEqualTo(3);
    KeysetHandle.Entry entry0 = keysetHandle.getAt(0);
    assertThat(entry0.getKey().getParameters())
        .isEqualTo(AesCmacParameters.create(/*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 16));
    assertThat(entry0.isPrimary()).isFalse();
    assertThat(entry0.getStatus()).isEqualTo(KeyStatus.DISABLED);

    KeysetHandle.Entry entry1 = keysetHandle.getAt(1);
    assertThat(entry1.isPrimary()).isTrue();
    assertThat(entry1.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry1.getKey().getParameters())
        .isEqualTo(
            AesCmacParameters.createForKeyset(
                /*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 10, AesCmacParameters.Variant.CRUNCHY));

    KeysetHandle.Entry entry2 = keysetHandle.getAt(2);
    assertThat(entry2.isPrimary()).isFalse();
    assertThat(entry2.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(keysetHandle.getAt(2).getKey().getParameters())
        .isEqualTo(
            AesCmacParameters.createForKeyset(
                /*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 13, AesCmacParameters.Variant.LEGACY));
  }

  @Test
  public void testBuilder_isPrimary_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    assertThat(builder.getAt(0).isPrimary()).isFalse();
    builder.getAt(0).makePrimary();
    assertThat(builder.getAt(0).isPrimary()).isTrue();
  }

  @Test
  public void testBuilder_setStatus_getStatus_works() throws Exception {
    KeysetHandle.Builder.Entry entry =
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId();
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.ENABLED);
    entry.setStatus(KeyStatus.DISABLED);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.DISABLED);
    entry.setStatus(KeyStatus.DESTROYED);
    assertThat(entry.getStatus()).isEqualTo(KeyStatus.DESTROYED);
  }

  @Test
  // Tests that withRandomId avoids collisions. We use 2^16 keys to make collision likely. The test
  // is about 4 seconds like this.
  public void testBuilder_withRandomId_doesNotHaveCollisions() throws Exception {
    // Test takes longer on Android; and a simple Java test suffices.
    assumeFalse(TestUtil.isAndroid());
    int numNonPrimaryKeys = 2 << 16;
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    for (int i = 0; i < numNonPrimaryKeys; i++) {
      builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    }
    KeysetHandle handle = builder.build();
    Set<Integer> idSet = new HashSet<>();
    for (int i = 0; i < handle.size(); ++i) {
      idSet.add(handle.getAt(i).getId());
    }
    assertThat(idSet).hasSize(numNonPrimaryKeys + 1);
  }

  @Test
  public void testBuilder_randomIdAfterFixedId_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withFixedId(777))
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .withRandomId()
                    .makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(2);
    assertThat(handle.getAt(0).getId()).isEqualTo(777);
  }

  @Test
  public void testBuilder_fixedIdAfterRandomId_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withFixedId(777));
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_removeAt_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.addEntry(
        KeysetHandle.generateEntryFromParameters(
                AesCmacParameters.create(/*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 13))
            .withRandomId()
            .makePrimary());
    builder.removeAt(0);
    KeysetHandle handle = builder.build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().getParameters())
        .isEqualTo(AesCmacParameters.create(/*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 13));
  }

  @Test
  public void testBuilder_size_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    assertThat(builder.size()).isEqualTo(0);
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    assertThat(builder.size()).isEqualTo(1);
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    assertThat(builder.size()).isEqualTo(2);
  }

  @Test
  public void testBuilder_noPrimary_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_removedPrimary_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.removeAt(0);
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_addPrimary_clearsOtherPrimary() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    assertThat(builder.getAt(0).isPrimary()).isFalse();
  }

  @Test
  public void testBuilder_setPrimary_clearsOtherPrimary() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.getAt(1).makePrimary();
    assertThat(builder.getAt(0).isPrimary()).isFalse();
  }

  @Test
  public void testBuilder_noIdSet_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_doubleId_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").makePrimary().withFixedId(777));
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withFixedId(777));
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testBuilder_createFromKeysetHandle_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").makePrimary().withRandomId());
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    KeysetHandle originalKeyset = builder.build();

    builder = KeysetHandle.newBuilder(originalKeyset);
    KeysetHandle secondKeyset = builder.build();

    assertThat(secondKeyset.size()).isEqualTo(2);
    assertThat(secondKeyset.getAt(0).getKey().equalsKey(originalKeyset.getAt(0).getKey())).isTrue();
    assertThat(secondKeyset.getAt(1).getKey().equalsKey(originalKeyset.getAt(1).getKey())).isTrue();
    assertThat(secondKeyset.getAt(0).getStatus()).isEqualTo(originalKeyset.getAt(0).getStatus());
    assertThat(secondKeyset.getAt(1).getStatus()).isEqualTo(originalKeyset.getAt(1).getStatus());
    assertThat(secondKeyset.getAt(0).isPrimary()).isTrue();
  }

  @Test
  public void testImportKey_withoutIdRequirement_withFixedId_works() throws Exception {
    AesCmacParameters params = AesCmacParameters.create(/*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 10);
    AesCmacKey key = AesCmacKey.create(params, SecretBytes.randomBytes(32));
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(102).makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(102);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withoutIdRequirement_noIdAssigned_throws() throws Exception {
    AesCmacParameters params = AesCmacParameters.create(/*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 10);
    AesCmacKey key = AesCmacKey.create(params, SecretBytes.randomBytes(32));
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withoutIdRequirement_withRandomId_works() throws Exception {
    AesCmacParameters params = AesCmacParameters.create(/*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 10);
    AesCmacKey key = AesCmacKey.create(params, SecretBytes.randomBytes(32));
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_noId_works() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.createForKeyset(
            /*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 10, AesCmacParameters.Variant.TINK);
    AesCmacKey key =
        AesCmacKey.createForKeyset(params, SecretBytes.randomBytes(32), /*idRequirement=*/ 105);
    KeysetHandle handle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(105);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_randomId_throws() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.createForKeyset(
            /*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 10, AesCmacParameters.Variant.TINK);
    AesCmacKey key =
        AesCmacKey.createForKeyset(params, SecretBytes.randomBytes(32), /*idRequirement=*/ 105);
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withIdRequirement_explicitlySetToCorrectId_works() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.createForKeyset(
            /*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 10, AesCmacParameters.Variant.TINK);
    AesCmacKey key =
        AesCmacKey.createForKeyset(params, SecretBytes.randomBytes(32), /*idRequirement=*/ 105);
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(105).makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(105);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_explicitlySetToWrongId_throws() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.createForKeyset(
            /*keySizeBytes=*/ 32, /*tagSizeBytes=*/ 10, AesCmacParameters.Variant.TINK);
    AesCmacKey key =
        AesCmacKey.createForKeyset(params, SecretBytes.randomBytes(32), /*idRequirement=*/ 105);
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(106).makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testAddEntry_addTwice_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    KeysetHandle.Builder.Entry entry =
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").makePrimary().withRandomId();
    builder.addEntry(entry);
    assertThrows(IllegalStateException.class, () -> builder.addEntry(entry));
  }

  @Test
  public void testSetStatusNull_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
            .makePrimary()
            .withRandomId()
            .setStatus(null));
    assertThrows(GeneralSecurityException.class, builder::build);
  }
}
