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
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesEaxKeyManager;
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
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.HmacKey;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.monitoring.MonitoringAnnotations;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.EcdsaPrivateKey;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.SignatureConfig;
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

/**
 * Tests for {@link KeysetHandle}.
 *
 * <p>Please note, that in relation to the {@link PrimitiveSet#fullPrimitive} this file only tests
 * the legacy scenario where the {@link PrimitiveSet#primitive} is set and {@link
 * PrimitiveSet#fullPrimitive} isn't; the other scenarios are tested in
 * {@link KeysetHandleFullPrimitiveTest}.
 */
@RunWith(JUnit4.class)
public class KeysetHandleTest {

  @Rule public final Expect expect = Expect.create();

  private static interface EncryptOnly {
    byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException;
  }

  private static class AeadToEncryptOnlyWrapper implements PrimitiveWrapper<Aead, EncryptOnly> {

    private static final AeadToEncryptOnlyWrapper WRAPPER = new AeadToEncryptOnlyWrapper();

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

    static void register() throws GeneralSecurityException {
      Registry.registerPrimitiveWrapper(WRAPPER);
    }
  }

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    MacConfig.register();
    AeadConfig.register();
    SignatureConfig.register();
    AeadToEncryptOnlyWrapper.register();
  }

  @SuppressWarnings("deprecation") // This is a test for the deprecated function
  @Test
  public void deprecated_getKeys() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES128_EAX").withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES128_EAX")
                    .withRandomId()
                    .makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES128_EAX").withRandomId())
            .build();
    Keyset keyset = handle.getKeyset();

    List<KeyHandle> keysetKeys = handle.getKeys();

    expect.that(keysetKeys).hasSize(3);
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
  public void generateNew_tink_shouldWork() throws Exception {
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
  public void generateNew_raw_shouldWork() throws Exception {
    KeyTemplate template = KeyTemplates.get("AES128_EAX_RAW");

    KeysetHandle handle = KeysetHandle.generateNew(template);

    Keyset keyset = handle.getKeyset();
    expect.that(keyset.getKeyCount()).isEqualTo(1);
    Keyset.Key key = keyset.getKey(0);
    expect.that(keyset.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    expect.that(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    expect.that(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
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

  @SuppressWarnings("deprecation")  // This is a test for the deprecated function
  @Test
  public void deprecated_createFromKey_shouldWork() throws Exception {
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
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
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
    PublicKeySign signer = privateHandle.getPrimitive(PublicKeySign.class);
    PublicKeyVerify verifier = publicHandle.getPrimitive(PublicKeyVerify.class);
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
        GeneralSecurityException.class, () -> KeysetHandle.read(reader, /* masterKey= */ null));
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
    Object unused = encryptOnlyWithAnnotations.encrypt(message);
    List<FakeMonitoringClient.LogEntry> entries = fakeMonitoringClient.getLogEntries();
    assertThat(entries).hasSize(1);
    assertThat(entries.get(0).getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  }

  @SuppressWarnings("deprecation")  // This is a test for the deprecated function
  @Test
  public void deprecated_readNoSecretWithBytesInput_sameAs_parseKeysetWithoutSecret()
      throws Exception {
    // Public keyset should have the same output
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    byte[] serializedPublicKeyset = privateHandle.getPublicKeysetHandle().getKeyset().toByteArray();

    KeysetHandle readNoSecretOutput = KeysetHandle.readNoSecret(serializedPublicKeyset);
    KeysetHandle parseKeysetWithoutSecretOutput =
        TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedPublicKeyset);
    expect
        .that(readNoSecretOutput.getKeyset())
        .isEqualTo(parseKeysetWithoutSecretOutput.getKeyset());

    // Symmetric Keyset should fail
    byte[] serializedSymmetricKeyset =
        TestUtil.createKeyset(
                TestUtil.createKey(
                    TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.TINK))
            .toByteArray();
    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(serializedSymmetricKeyset));
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedSymmetricKeyset));

    // Private Keyset should fail
    byte[] serializedPrivateKeyset = privateHandle.getKeyset().toByteArray();
    assertThrows(
        GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(serializedPrivateKeyset));
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(serializedPrivateKeyset));

    // Empty Keyset should fail
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(new byte[0]));
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(new byte[0]));

    // Invalid Keyset should fail
    byte[] proto = new byte[] {0x00, 0x01, 0x02};
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.readNoSecret(proto));
    assertThrows(
        GeneralSecurityException.class,
        () -> TinkProtoKeysetFormat.parseKeysetWithoutSecret(proto));
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_shouldWork() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
    Keyset keyset = privateHandle.getPublicKeysetHandle().getKeyset();
    byte[] serializedKeyset = keyset.toByteArray();

    Keyset readKeyset =
        KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(serializedKeyset)).getKeyset();

    expect.that(readKeyset).isEqualTo(keyset);
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_withTypeSymmetric_shouldThrow() throws Exception {
    String keyValue = "01234567890123456";
    byte[] serializedKeyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData(keyValue.getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK)).toByteArray();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(serializedKeyset)));
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_withTypeAsymmetricPrivate_shouldThrow()
      throws Exception {
    byte[] serializedKeyset =
        KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256")).getKeyset().toByteArray();

    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(serializedKeyset)));
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_withEmptyKeyset_shouldThrow() throws Exception {
    byte[] emptySerializedKeyset = new byte[0];
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(emptySerializedKeyset)));
  }

  @Test
  public void readNoSecretWithBinaryKeysetReader_withInvalidKeyset_shouldThrow() throws Exception {
    byte[] invalidSerializedKeyset = new byte[] {0x00, 0x01, 0x02};
    assertThrows(
        GeneralSecurityException.class,
        () -> KeysetHandle.readNoSecret(BinaryKeysetReader.withBytes(invalidSerializedKeyset)));
  }

  @Test
  public void writeNoSecretThenReadNoSecret_returnsSameKeyset() throws Exception {
    KeysetHandle privateHandle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));
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
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("ECDSA_P256"));

    assertThrows(GeneralSecurityException.class, () -> handle.writeNoSecret(/* writer= */ null));
  }

  @SuppressWarnings("deprecation")  // This is a test for the deprecated function
  @Test
  public void deprecated_primaryKey_shouldWork() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("AES128_EAX").withFixedId(123))
        .addEntry(
            KeysetHandle.generateEntryFromParametersName("HMAC_SHA256_256BITTAG")
                .withFixedId(234).makePrimary())
        .build();

    KeyHandle keyHandle = handle.primaryKey();
    assertThat(keyHandle.getId()).isEqualTo(234);
  }

  @SuppressWarnings("deprecation")  // This is a test for the deprecated function
  @Test
  public void deprecated_primaryKey_primaryNotPresent_shouldThrow() throws Exception {
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle =
        KeysetHandle.fromKeyset(Keyset.newBuilder(keyset).setPrimaryKeyId(77).build());

    assertThrows(GeneralSecurityException.class, handle::primaryKey);
  }

  @Test
  public void testGetAt_singleKeyWithRegisteredProtoSerialization_works() throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
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
    assertThat(entry.getKey().getClass()).isEqualTo(HmacKey.class);
  }

  @Test
  public void getAt_invalidKeyWithRegisteredProtoSerialization_throwsIllegalStateException()
      throws Exception {
    // HmacKey's proto serialization HmacProtoSerialization is registed in HmacKeyManager.
    com.google.crypto.tink.proto.HmacKey invalidProtoHmacKey =
        com.google.crypto.tink.proto.HmacKey.newBuilder()
            .setVersion(999)
            .setKeyValue(ByteString.copyFromUtf8("01234567890123456"))
            .setParams(HmacParams.newBuilder().setHash(HashType.UNKNOWN_HASH).setTagSize(0))
            .build();
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createKeyData(
                    invalidProtoHmacKey,
                    "type.googleapis.com/google.crypto.tink.HmacKey",
                    KeyData.KeyMaterialType.SYMMETRIC),
                42,
                KeyStatusType.ENABLED,
                OutputPrefixType.TINK));
    KeysetHandle handle = KeysetHandle.fromKeyset(keyset);
    assertThat(handle.size()).isEqualTo(1);
    assertThrows(IllegalStateException.class, () -> handle.getAt(0));
  }

  @Test
  public void testGetAt_singleKeyWithoutRegisteredProtoSerialization_works() throws Exception {
    // HkdfPrfKey does currently not have a serialization registed.
    Keyset keyset =
        TestUtil.createKeyset(
            TestUtil.createKey(
                TestUtil.createPrfKeyData("01234567890123456".getBytes(UTF_8)),
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
        .isEqualTo(AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(16).build());
  }

  @Test
  public void keysetRotationWithBuilder_works() throws Exception {
    KeysetHandle oldKeyset =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW")
                    .withRandomId()
                    .makePrimary())
            .build();

    // Add new key.
    KeysetHandle keysetWithNewKey =
        KeysetHandle.newBuilder(oldKeyset)
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW").withRandomId())
            .build();

    // Make latest key primary.
    KeysetHandle.Builder builder = KeysetHandle.newBuilder(keysetWithNewKey);
    builder.getAt(builder.size() - 1).makePrimary();
    KeysetHandle keysetWithNewPrimary = builder.build();

    assertThat(oldKeyset.size()).isEqualTo(1);

    assertThat(keysetWithNewKey.size()).isEqualTo(2);
    assertThat(keysetWithNewKey.getAt(0).isPrimary()).isTrue();
    assertThat(keysetWithNewKey.getAt(1).isPrimary()).isFalse();

    assertThat(keysetWithNewPrimary.size()).isEqualTo(2);
    assertThat(keysetWithNewPrimary.getAt(0).isPrimary()).isFalse();
    assertThat(keysetWithNewPrimary.getAt(1).isPrimary()).isTrue();
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
                        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
                            .setVariant(Variant.CRUNCHY).build())
                    .withRandomId()
                    .makePrimary())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13)
                            .setVariant(Variant.LEGACY).build())
                    .withRandomId())
            .build();
    assertThat(keysetHandle.size()).isEqualTo(3);
    KeysetHandle.Entry entry0 = keysetHandle.getAt(0);
    assertThat(entry0.getKey().getParameters())
        .isEqualTo(AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(16).build());
    assertThat(entry0.isPrimary()).isFalse();
    assertThat(entry0.getStatus()).isEqualTo(KeyStatus.DISABLED);

    KeysetHandle.Entry entry1 = keysetHandle.getAt(1);
    assertThat(entry1.isPrimary()).isTrue();
    assertThat(entry1.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(entry1.getKey().getParameters())
        .isEqualTo(
            AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
                .setVariant(Variant.CRUNCHY).build());

    KeysetHandle.Entry entry2 = keysetHandle.getAt(2);
    assertThat(entry2.isPrimary()).isFalse();
    assertThat(entry2.getStatus()).isEqualTo(KeyStatus.ENABLED);
    assertThat(keysetHandle.getAt(2).getKey().getParameters())
        .isEqualTo(
            AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13)
                .setVariant(Variant.LEGACY).build());
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
    int numNonPrimaryKeys = 1 << 16;
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
  public void testBuilder_deprecated_removeAt_works() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
            .withRandomId()
            .setStatus(KeyStatus.DISABLED));
    builder.addEntry(
        KeysetHandle.generateEntryFromParameters(
                AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13).build())
            .withRandomId()
            .makePrimary()
            .setStatus(KeyStatus.ENABLED));
    KeysetHandle.Builder.Entry removedEntry = builder.removeAt(0);
    assertThat(removedEntry.getStatus()).isEqualTo(KeyStatus.DISABLED);
    KeysetHandle handle = builder.build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getKey().getParameters())
        .isEqualTo(AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13).build());
  }

  @Test
  public void testBuilder_deprecated_removeAtInvalidIndex_throws() throws Exception {
    KeysetHandle.Builder builder = KeysetHandle.newBuilder();
    builder.addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId());
    builder.addEntry(
        KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId().makePrimary());
    assertThrows(IndexOutOfBoundsException.class, () -> builder.removeAt(2));
  }

  @Test
  public void testBuilder_deleteAt_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParameters(
                        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13).build())
                    .withRandomId()
                    .makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(2);

    KeysetHandle handle2 = KeysetHandle.newBuilder(handle).deleteAt(0).build();

    assertThat(handle2.size()).isEqualTo(1);
    assertThat(handle2.getAt(0).getKey().getParameters())
        .isEqualTo(AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(13).build());
  }

  @Test
  public void testBuilder_deleteAtInvalidIndex_works() throws Exception {
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId())
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .withRandomId()
                    .makePrimary())
            .build();
    assertThat(handle.size()).isEqualTo(2);

    assertThrows(
        IndexOutOfBoundsException.class, () -> KeysetHandle.newBuilder(handle).deleteAt(2));
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
  public void testBuilder_deletedPrimary_throws() throws Exception {
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC")
                    .withRandomId()
                    .makePrimary())
            .addEntry(KeysetHandle.generateEntryFromParametersName("AES256_CMAC").withRandomId())
            .deleteAt(0);
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
  public void testBuilder_buildTwice_fails() throws Exception {
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.generateEntryFromParametersName("AES256_CMAC_RAW")
                    .withRandomId()
                    .makePrimary());

    Object unused = builder.build();
    // We disallow calling build on the same builder twice. The reason is that build assigns IDs
    // which were marked with "withRandomId()". Doing this twice results in incompatible keysets,
    // which would be confusing.
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withoutIdRequirement_withFixedId_works() throws Exception {
    AesCmacParameters params = AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
        .build();
    AesCmacKey key = AesCmacKey.builder().setParameters(params)
        .setAesKeyBytes(SecretBytes.randomBytes(32)).build();
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
    AesCmacParameters params = AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
        .build();
    AesCmacKey key = AesCmacKey.builder().setParameters(params)
        .setAesKeyBytes(SecretBytes.randomBytes(32)).build();
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withoutIdRequirement_withRandomId_works() throws Exception {
    AesCmacParameters params = AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10)
        .build();
    AesCmacKey key = AesCmacKey.builder().setParameters(params)
        .setAesKeyBytes(SecretBytes.randomBytes(32)).build();
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
        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10).setVariant(Variant.TINK)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(params)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(105)
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder().addEntry(KeysetHandle.importKey(key).makePrimary()).build();
    assertThat(handle.size()).isEqualTo(1);
    assertThat(handle.getAt(0).getId()).isEqualTo(105);
    assertThat(handle.getAt(0).getKey().equalsKey(key)).isTrue();
  }

  @Test
  public void testImportKey_withIdRequirement_randomId_throws() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10).setVariant(Variant.TINK)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(params)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(105)
            .build();
    KeysetHandle.Builder builder =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withRandomId().makePrimary());
    assertThrows(GeneralSecurityException.class, builder::build);
  }

  @Test
  public void testImportKey_withIdRequirement_explicitlySetToCorrectId_works() throws Exception {
    AesCmacParameters params =
        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10).setVariant(Variant.TINK)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(params)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(105)
            .build();
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
        AesCmacParameters.builder().setKeySizeBytes(32).setTagSizeBytes(10).setVariant(Variant.TINK)
            .build();
    AesCmacKey key =
        AesCmacKey.builder()
            .setParameters(params)
            .setAesKeyBytes(SecretBytes.randomBytes(32))
            .setIdRequirement(105)
            .build();
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
