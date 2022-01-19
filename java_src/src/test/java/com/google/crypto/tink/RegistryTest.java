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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.Ed25519KeyFormat;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.signature.EcdsaSignKeyManager;
import com.google.crypto.tink.signature.SignatureKeyTemplates;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.crypto.tink.testing.TestUtil.DummyAead;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for Registry. */
@RunWith(JUnit4.class)
public class RegistryTest {
  private static class CustomAeadKeyManager implements KeyManager<Aead> {
    public CustomAeadKeyManager(String typeUrl) {
      this.typeUrl = typeUrl;
    }

    private final String typeUrl;

    @Override
    public Aead getPrimitive(ByteString proto) throws GeneralSecurityException {
      return new DummyAead();
    }

    @Override
    public Aead getPrimitive(MessageLite proto) throws GeneralSecurityException {
      return new DummyAead();
    }

    @Override
    public MessageLite newKey(ByteString template) throws GeneralSecurityException {
      throw new GeneralSecurityException("Not Implemented");
    }

    @Override
    public MessageLite newKey(MessageLite template) throws GeneralSecurityException {
      throw new GeneralSecurityException("Not Implemented");
    }

    @Override
    public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
      return KeyData.newBuilder()
            .setTypeUrl(typeUrl)
            .setValue(serializedKeyFormat)
            .build();
    }

    @Override
    public boolean doesSupport(String typeUrl) {
      return typeUrl.equals(this.typeUrl);
    }

    @Override
    public String getKeyType() {
      return this.typeUrl;
    }

    @Override
    public int getVersion() {
      return 0;
    }

    @Override
    public Class<Aead> getPrimitiveClass() {
      return Aead.class;
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

  @Before
  public void setUp() throws GeneralSecurityException {
    TinkFipsUtil.unsetFipsRestricted();
    Registry.reset();
    TinkConfig.register();
    Registry.registerPrimitiveWrapper(new AeadToEncryptOnlyWrapper());
  }

  private void testGetKeyManagerShouldWork(String typeUrl, String className) throws Exception {
    assertThat(Registry.getKeyManager(typeUrl).getClass().toString()).contains(className);
  }

  @Test
  public void testGetKeyManager_legacy_shouldWork() throws Exception {
    testGetKeyManagerShouldWork(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL, "KeyManagerImpl");
    testGetKeyManagerShouldWork(AeadConfig.AES_EAX_TYPE_URL, "KeyManagerImpl");
    testGetKeyManagerShouldWork(MacConfig.HMAC_TYPE_URL, "KeyManagerImpl");
  }

  @Test
  public void testGetKeyManager_shouldWorkAesEax() throws Exception {
    assertThat(
            Registry.getKeyManager(AeadConfig.AES_EAX_TYPE_URL, Aead.class).getClass().toString())
        .contains("KeyManagerImpl");
  }

  @Test
  public void testGetKeyManager_shouldWorkHmac() throws Exception {
    assertThat(Registry.getKeyManager(MacConfig.HMAC_TYPE_URL, Mac.class).getClass().toString())
        .contains("KeyManagerImpl");
  }

  @Test
  public void testGetKeyManager_legacy_wrongType_shouldThrowException() throws Exception {
    KeyManager<Aead> wrongType = Registry.getKeyManager(MacConfig.HMAC_TYPE_URL);
    HmacKey hmacKey = (HmacKey) Registry.newKey(MacKeyTemplates.HMAC_SHA256_128BITTAG);

    ClassCastException e =
        assertThrows(
            ClassCastException.class,
            () -> {
              Aead unused = wrongType.getPrimitive(hmacKey);
            });
    assertExceptionContains(e, "com.google.crypto.tink.Aead");
    assertExceptionContains(e, "com.google.crypto.tink.subtle.PrfMac");
  }

  @Test
  public void testGetKeyManager_wrongType_shouldThrowException() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Registry.getKeyManager(MacConfig.HMAC_TYPE_URL, Aead.class));
    assertExceptionContains(e, "com.google.crypto.tink.Mac");
    assertExceptionContains(e, "com.google.crypto.tink.Aead not supported");
  }

  @Test
  public void testGetKeyManager_legacy_badTypeUrl_shouldThrowException() throws Exception {
    String badTypeUrl = "bad type URL";

    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Registry.getKeyManager(badTypeUrl));
    assertExceptionContains(e, "No key manager found");
    assertExceptionContains(e, badTypeUrl);
  }

  @Test
  public void testGetKeyManager_badTypeUrl_shouldThrowException() throws Exception {
    String badTypeUrl = "bad type URL";

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> Registry.getKeyManager(badTypeUrl, Aead.class));
    assertExceptionContains(e, "No key manager found");
    assertExceptionContains(e, badTypeUrl);
  }

  @Test
  public void testGetUntypedKeyManager_shouldWorkHmac() throws Exception {
    assertThat(Registry.getUntypedKeyManager(MacConfig.HMAC_TYPE_URL).getClass().toString())
        .contains("KeyManagerImpl");
  }

  @Test
  public void testRegisterKeyManager_keyManagerIsNull_shouldThrowException() throws Exception {
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Registry.registerKeyManager(null));
    assertThat(e.toString()).contains("must be non-null");
  }

  @Test
  public void testRegisterKeyManager_moreRestrictedNewKeyAllowed_shouldWork() throws Exception {
    String typeUrl = "someTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl));
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), false);
  }

  @Test
  public void testRegisterKeyManager_sameNewKeyAllowed_shouldWork() throws Exception {
    String typeUrl = "someOtherTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl));
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), true);
  }

  @Test
  public void testRegisterKeyManager_lessRestrictedNewKeyAllowed_shouldThrowException()
      throws Exception {
    String typeUrl = "yetAnotherTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), false);

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), true));
  }

  @Test
  public void testRegisterKeyManager_keyManagerFromAnotherClass_shouldThrowException()
      throws Exception {
    // This should not overwrite the existing manager.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                Registry.registerKeyManager(
                    new CustomAeadKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL)));
    assertThat(e.toString()).contains("already registered");

    KeyManager<Aead> manager = Registry.getKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL);
    assertThat(manager.getClass().toString()).contains("KeyManagerImpl");
  }

  @Test
  public void testRegisterKeyManager_deprecated_keyManagerIsNull_shouldThrowException()
      throws Exception {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> Registry.registerKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL, null));
    assertThat(e.toString()).contains("must be non-null");
  }

  @Test
  public void testRegisterKeyManager_deprecated_withKeyTypeNotSupported_shouldThrowException()
      throws Exception {
    String typeUrl = "yetSomeOtherTypeUrl";
    String differentTypeUrl = "differentTypeUrl";
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Registry.registerKeyManager(differentTypeUrl, new CustomAeadKeyManager(typeUrl)));
    assertExceptionContains(e, "Manager does not support key type " + differentTypeUrl);
  }

  @Test
  public void testRegisterKeyManager_deprecated_moreRestrictedNewKeyAllowed_shouldWork()
      throws Exception {
    String typeUrl = "typeUrl";
    Registry.registerKeyManager(typeUrl, new CustomAeadKeyManager(typeUrl));

    try {
      Registry.registerKeyManager(typeUrl, new CustomAeadKeyManager(typeUrl), false);
    } catch (GeneralSecurityException e) {
      fail("repeated registrations of the same key manager should work");
    }
  }

  @Test
  public void testRegisterKeyManager_deprecated_lessRestrictedNewKeyAllowed_shouldThrowException()
      throws Exception {
    String typeUrl = "totallyDifferentTypeUrl";
    Registry.registerKeyManager(typeUrl, new CustomAeadKeyManager(typeUrl), false);

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(typeUrl, new CustomAeadKeyManager(typeUrl), true));
  }

  @Test
  public void testRegisterKeyManager_deprecated_keyManagerFromAnotherClass_shouldThrowException()
      throws Exception {
    // This should not overwrite the existing manager.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                Registry.registerKeyManager(
                    AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL,
                    new CustomAeadKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL)));
    assertThat(e.toString()).contains("already registered");

    KeyManager<Aead> manager = Registry.getKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL);
    assertThat(manager.getClass().toString()).contains("KeyManagerImpl");
  }

  @Test
  public void testGetPublicKeyData_shouldWork() throws Exception {
    KeyData privateKeyData = Registry.newKeyData(SignatureKeyTemplates.ECDSA_P256);
    KeyData publicKeyData = Registry.getPublicKeyData(privateKeyData.getTypeUrl(),
        privateKeyData.getValue());
    PublicKeyVerify verifier = Registry.<PublicKeyVerify>getPrimitive(publicKeyData);
    PublicKeySign signer = Registry.<PublicKeySign>getPrimitive(privateKeyData);
    byte[] message = "Nice test message".getBytes(UTF_8);
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void testGetPublicKeyData_shouldThrow() throws Exception {
    KeyData keyData = Registry.newKeyData(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Registry.getPublicKeyData(keyData.getTypeUrl(), keyData.getValue()));
    assertThat(e.toString()).contains("not a PrivateKeyManager");
  }

  @Test
  public void testGetInputPrimitive_encryptOnly() throws Exception {
    assertThat(Registry.getInputPrimitive(EncryptOnly.class)).isEqualTo(Aead.class);
    assertThat(Registry.getInputPrimitive(Aead.class)).isEqualTo(Aead.class);
  }

  @Test
  public void testGetPrimitive_legacy_aesGcm_shouldWork() throws Exception {
    AesEaxKey aesEaxKey =
        (AesEaxKey) Registry.newKey(AesEaxKeyManager.aes128EaxTemplate().getProto());
    KeyData aesEaxKeyData = Registry.newKeyData(AesEaxKeyManager.aes128EaxTemplate().getProto());
    Aead aead = Registry.getPrimitive(aesEaxKeyData);

    assertThat(aesEaxKey.getKeyValue().size()).isEqualTo(16);
    assertThat(aesEaxKeyData.getTypeUrl()).isEqualTo(AeadConfig.AES_EAX_TYPE_URL);
    // This might break when we add native implementations.
    assertThat(aead.getClass()).isEqualTo(AesEaxJce.class);
  }

  @Test
  public void testGetPrimitive_aesGcm_shouldWork() throws Exception {
    AesEaxKey aesEaxKey =
        (AesEaxKey) Registry.newKey(AesEaxKeyManager.aes128EaxTemplate().getProto());
    KeyData aesEaxKeyData = Registry.newKeyData(AesEaxKeyManager.aes128EaxTemplate().getProto());
    Aead aead = Registry.getPrimitive(aesEaxKeyData, Aead.class);

    assertThat(aesEaxKey.getKeyValue().size()).isEqualTo(16);
    assertThat(aesEaxKeyData.getTypeUrl()).isEqualTo(AeadConfig.AES_EAX_TYPE_URL);
    // This might break when we add native implementations.
    assertThat(aead.getClass()).isEqualTo(AesEaxJce.class);
  }

  @Test
  public void testGetPrimitive_legacy_hmac_shouldWork() throws Exception {
    com.google.crypto.tink.proto.KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    HmacKey hmacKey = (HmacKey) Registry.newKey(template);
    KeyData hmacKeyData = Registry.newKeyData(template);
    Mac mac = Registry.getPrimitive(hmacKeyData);

    assertThat(hmacKey.getKeyValue().size()).isEqualTo(32);
    assertThat(hmacKey.getParams().getTagSize()).isEqualTo(16);
    assertThat(hmacKey.getParams().getHash()).isEqualTo(HashType.SHA256);
    assertThat(hmacKeyData.getTypeUrl()).isEqualTo(MacConfig.HMAC_TYPE_URL);
    // This might break when we add native implementations.
    assertThat(mac.getClass()).isEqualTo(PrfMac.class);
  }

  @Test
  public void testGetPrimitive_hmac_shouldWork() throws Exception {
    com.google.crypto.tink.proto.KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    HmacKey hmacKey = (HmacKey) Registry.newKey(template);
    KeyData hmacKeyData = Registry.newKeyData(template);
    Mac mac = Registry.getPrimitive(hmacKeyData, Mac.class);

    assertThat(hmacKey.getKeyValue().size()).isEqualTo(32);
    assertThat(hmacKey.getParams().getTagSize()).isEqualTo(16);
    assertThat(hmacKey.getParams().getHash()).isEqualTo(HashType.SHA256);
    assertThat(hmacKeyData.getTypeUrl()).isEqualTo(MacConfig.HMAC_TYPE_URL);
    // This might break when we add native implementations.
    assertThat(mac.getClass()).isEqualTo(PrfMac.class);
  }

  @Test
  public void
      testNewKeyData_keyTemplateProto_registeredTypeUrl_returnsCustomAeadKeyManagerNewKeyData()
          throws Exception {
    String typeUrl = "testNewKeyDataTypeUrl";
    CustomAeadKeyManager km = new CustomAeadKeyManager(typeUrl);
    ByteString keyformat = ByteString.copyFromUtf8("testNewKeyDataKeyFormat");
    Registry.registerKeyManager(km);
    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
        .setValue(keyformat)
        .setTypeUrl(typeUrl)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();

    assertThat(Registry.newKeyData(template)).isEqualTo(km.newKeyData(keyformat));
  }

  @Test
  public void testNewKeyData_keyTemplateProto_registeredTypeUrlNewKeyAllowedFalse_throwsException()
      throws Exception {
    String typeUrl = "testNewKeyDataTypeUrl";
    CustomAeadKeyManager km = new CustomAeadKeyManager(typeUrl);
    ByteString keyformat = ByteString.copyFromUtf8("testNewKeyDataKeyFormat");
    Registry.registerKeyManager(km, false);
    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
        .setValue(keyformat)
        .setTypeUrl(typeUrl)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();

    assertThrows(GeneralSecurityException.class, () -> Registry.newKeyData(template));
  }

  @Test
  public void testNewKeyData_keyTemplateProto_unregisteredTypeUrl_throwsException()
      throws Exception {
    String typeUrl = "testNewKeyDataTypeUrl";
    ByteString keyformat = ByteString.copyFromUtf8("testNewKeyDataKeyFormat");
    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
        .setValue(keyformat)
        .setTypeUrl(typeUrl)
        .setOutputPrefixType(OutputPrefixType.TINK)
        .build();

    assertThrows(GeneralSecurityException.class, () -> Registry.newKeyData(template));
  }

  @Test
  public void
      testNewKeyData_keyTemplateClass_registeredTypeUrl_returnsCustomAeadKeyManagerNewKeyData()
          throws Exception {
    String typeUrl = "testNewKeyDataTypeUrl";
    CustomAeadKeyManager km = new CustomAeadKeyManager(typeUrl);
    ByteString keyformat = ByteString.copyFromUtf8("testNewKeyDataKeyFormat");
    Registry.registerKeyManager(km);
    com.google.crypto.tink.KeyTemplate template =
        com.google.crypto.tink.KeyTemplate.create(
            typeUrl, keyformat.toByteArray(),
            com.google.crypto.tink.KeyTemplate.OutputPrefixType.TINK);

    assertThat(Registry.newKeyData(template)).isEqualTo(km.newKeyData(keyformat));
  }

  @Test
  public void testNewKeyData_keyTemplateClass_registeredTypeUrlNewKeyAllowedFalse_throwsException()
      throws Exception {
    String typeUrl = "testNewKeyDataTypeUrl";
    CustomAeadKeyManager km = new CustomAeadKeyManager(typeUrl);
    ByteString keyformat = ByteString.copyFromUtf8("testNewKeyDataKeyFormat");
    Registry.registerKeyManager(km, false);
    com.google.crypto.tink.KeyTemplate template =
        com.google.crypto.tink.KeyTemplate.create(
            typeUrl, keyformat.toByteArray(),
            com.google.crypto.tink.KeyTemplate.OutputPrefixType.TINK);

    assertThrows(GeneralSecurityException.class, () -> Registry.newKeyData(template));
  }

  @Test
  public void testNewKeyData_keyTemplateClass_unregisteredTypeUrl_throwsException()
      throws Exception {
    String typeUrl = "testNewKeyDataTypeUrl";
    ByteString keyformat = ByteString.copyFromUtf8("testNewKeyDataKeyFormat");
    com.google.crypto.tink.KeyTemplate template =
        com.google.crypto.tink.KeyTemplate.create(
            typeUrl, keyformat.toByteArray(),
            com.google.crypto.tink.KeyTemplate.OutputPrefixType.TINK);

    assertThrows(GeneralSecurityException.class, () -> Registry.newKeyData(template));
  }

  private static Map<String, KeyTypeManager.KeyFactory.KeyFormat<AesGcmKeyFormat>>
      createTestAesGcmKeyFormats() {
    Map<String, KeyTypeManager.KeyFactory.KeyFormat<AesGcmKeyFormat>> formats = new HashMap<>();
    formats.put(
        "TINK",
        new KeyTypeManager.KeyFactory.KeyFormat<>(
            AesGcmKeyFormat.newBuilder().setKeySize(16).build(),
            KeyTemplate.OutputPrefixType.TINK));
    formats.put(
        "RAW",
        new KeyTypeManager.KeyFactory.KeyFormat<>(
            AesGcmKeyFormat.newBuilder().setKeySize(32).build(), KeyTemplate.OutputPrefixType.RAW));
    return Collections.unmodifiableMap(formats);
  }

  /** Implementation of a KeyTypeManager for testing. */
  private static class TestKeyTypeManager extends KeyTypeManager<AesGcmKey> {
    private Map<String, KeyFactory.KeyFormat<AesGcmKeyFormat>> keyFormats =
        createTestAesGcmKeyFormats();

    public TestKeyTypeManager() {
      super(
          AesGcmKey.class,
          new PrimitiveFactory<Aead, AesGcmKey>(Aead.class) {
            @Override
            public Aead getPrimitive(AesGcmKey key) throws GeneralSecurityException {
              return new AesGcmJce(key.getKeyValue().toByteArray());
            }
          },
          new PrimitiveFactory<FakeAead, AesGcmKey>(FakeAead.class) {
            @Override
            public FakeAead getPrimitive(AesGcmKey key) {
              return new FakeAead();
            }
          });
    }

    public TestKeyTypeManager(Map<String, KeyFactory.KeyFormat<AesGcmKeyFormat>> keyFormats) {
      super(
          AesGcmKey.class,
          new PrimitiveFactory<Aead, AesGcmKey>(Aead.class) {
            @Override
            public Aead getPrimitive(AesGcmKey key) throws GeneralSecurityException {
              return new AesGcmJce(key.getKeyValue().toByteArray());
            }
          },
          new PrimitiveFactory<FakeAead, AesGcmKey>(FakeAead.class) {
            @Override
            public FakeAead getPrimitive(AesGcmKey key) {
              return new FakeAead();
            }
          });
      this.keyFormats = keyFormats;
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
    public void validateKey(AesGcmKey keyProto) throws GeneralSecurityException {
      // Throw by hand so we can verify the exception comes from here.
      if (keyProto.getKeyValue().size() != 16) {
        throw new GeneralSecurityException("validateKey(AesGcmKey) failed");
      }
    }

    @Override
    public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return AesGcmKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    @Override
    public KeyFactory<AesGcmKeyFormat, AesGcmKey> keyFactory() {
      return new KeyFactory<AesGcmKeyFormat, AesGcmKey>(AesGcmKeyFormat.class) {
        @Override
        public void validateKeyFormat(AesGcmKeyFormat format) throws GeneralSecurityException {
          // Throw by hand so we can verify the exception comes from here.
          if (format.getKeySize() != 16) {
            throw new GeneralSecurityException("validateKeyFormat(AesGcmKeyFormat) failed");
          }
        }

        @Override
        public AesGcmKeyFormat parseKeyFormat(ByteString byteString)
            throws InvalidProtocolBufferException {
          return AesGcmKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
        }

        @Override
        public AesGcmKey createKey(AesGcmKeyFormat format) throws GeneralSecurityException {
          return AesGcmKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
              .setVersion(getVersion())
              .build();
        }

        @Override
        public AesGcmKey deriveKey(AesGcmKeyFormat format, InputStream stream)
            throws GeneralSecurityException {
          byte[] pseudorandomness = new byte[format.getKeySize()];
          try {
            stream.read(pseudorandomness);
          } catch (IOException e) {
            throw new AssertionError("Unexpected IOException", e);
          }
          return AesGcmKey.newBuilder()
              .setKeyValue(ByteString.copyFrom(pseudorandomness))
              .setVersion(getVersion())
              .build();
        }

        @Override
        public Map<String, KeyFactory.KeyFormat<AesGcmKeyFormat>> keyFormats() {
          return keyFormats;
        }
      };
    }
  }

  @Test
  public void testRegisterKeyTypeManager() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
  }

  @Test
  public void testRegisterKeyTypeManager_keyTemplates_works() throws Exception {
    Registry.reset();
    assertThat(Registry.keyTemplates()).isEmpty();

    Registry.registerKeyManager(new TestKeyTypeManager(), true);

    assertThat(Registry.keyTemplates()).hasSize(2);
    assertThat(Registry.keyTemplates()).contains("TINK");
    assertThat(Registry.keyTemplates()).contains("RAW");
  }

  @Test
  public void testRegisterKeyTypeManager_disallowedNewKey_keyTemplates_works() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), false);
    assertThat(Registry.keyTemplates()).isEmpty();
  }

  @Test
  public void testRegisterKeyTypeManager_existingKeyManager_noNewKeyTemplate_works()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
  }

  @Test
  public void testRegisterKeyTypeManager_existingKeyManager_newKeyTemplate_fails()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);

    Map<String, KeyTypeManager.KeyFactory.KeyFormat<AesGcmKeyFormat>> formats = new HashMap<>();
    formats.put(
        "NEW_KEY_TEMPLATE_NAME",
        new KeyTypeManager.KeyFactory.KeyFormat<>(
            AesGcmKeyFormat.newBuilder().setKeySize(16).build(),
            KeyTemplate.OutputPrefixType.TINK));

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new TestKeyTypeManager(formats), true));
  }

  @Test
  public void testRegisterKeyTypeManager_newKeyManager_existingKeyTemplate_fails()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);

    TestKeyTypeManager manager =
        new TestKeyTypeManager() {
          @Override
          public String getKeyType() {
            return "blah";
          }
        };
    assertThrows(GeneralSecurityException.class, () -> Registry.registerKeyManager(manager, true));
  }

  @Test
  public void testRegisterKeyTypeManager_getKeyManagerAead_works() throws Exception {
    Registry.reset();
    TestKeyTypeManager testKeyTypeManager = new TestKeyTypeManager();
    Registry.registerKeyManager(testKeyTypeManager, true);
    KeyManager<Aead> km = Registry.getKeyManager(testKeyTypeManager.getKeyType(), Aead.class);
    assertThat(km.getKeyType()).isEqualTo(testKeyTypeManager.getKeyType());
  }

  @Test
  public void testRegisterKeyTypeManager_getKeyManagerFakeAead_works() throws Exception {
    Registry.reset();
    TestKeyTypeManager testKeyTypeManager = new TestKeyTypeManager();
    Registry.registerKeyManager(testKeyTypeManager, true);
    KeyManager<FakeAead> km =
        Registry.getKeyManager(testKeyTypeManager.getKeyType(), FakeAead.class);
    assertThat(km.getKeyType()).isEqualTo(testKeyTypeManager.getKeyType());
  }

  @Test
  public void testRegisterKeyTypeManager_getKeyManagerMac_throws() throws Exception {
    Registry.reset();
    TestKeyTypeManager testKeyTypeManager = new TestKeyTypeManager();
    Registry.registerKeyManager(testKeyTypeManager, true);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Registry.getKeyManager(testKeyTypeManager.getKeyType(), Mac.class));
    assertExceptionContains(e, "com.google.crypto.tink.Mac");
    assertExceptionContains(e, "com.google.crypto.tink.Aead");
        assertExceptionContains(e, "com.google.crypto.tink.RegistryTest.FakeAead");
  }

  // Checks that calling getUntypedKeyManager will return the keymanager for the *first* implemented
  // class in the constructor.
  @Test
  public void testRegisterKeyTypeManager_getUntypedKeyManager_returnsAead() throws Exception {
    Registry.reset();
    TestKeyTypeManager testKeyTypeManager = new TestKeyTypeManager();
    Registry.registerKeyManager(testKeyTypeManager, true);
    KeyManager<?> km = Registry.getUntypedKeyManager(testKeyTypeManager.getKeyType());
    assertThat(km.getPrimitiveClass()).isEqualTo(Aead.class);
  }

  @Test
  public void testRegisterKeyTypeManager_moreRestrictedNewKeyAllowed_shouldWork() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    Registry.registerKeyManager(new TestKeyTypeManager(), false);
  }

  @Test
  public void testRegisterKeyTypeManager_sameNewKeyAllowed_shouldWork() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    Registry.registerKeyManager(new TestKeyTypeManager(), false);
    Registry.registerKeyManager(new TestKeyTypeManager(), false);
  }

  @Test
  public void testRegisterKeyTypeManager_lessRestrictedNewKeyAllowed_throws() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), false);
    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new TestKeyTypeManager(), true));
  }

  @Test
  public void testRegisterKeyTypeManager_differentClass_throws() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new TestKeyTypeManager() {}, true));
  }

  @Test
  public void testRegisterKeyTypeManager_afterKeyManager_throws() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new CustomAeadKeyManager(new TestKeyTypeManager().getKeyType()));
    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new TestKeyTypeManager(), true));
  }

  @Test
  public void testRegisterKeyTypeManager_beforeKeyManager_throws() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            Registry.registerKeyManager(
                new CustomAeadKeyManager(new TestKeyTypeManager().getKeyType())));
  }

  @Test
  public void testParseKeyData_succeeds() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    AesGcmKey key =
        AesGcmKey.newBuilder()
            .setKeyValue(ByteString.copyFrom("0123456789abcdef".getBytes(UTF_8)))
            .build();
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(new TestKeyTypeManager().getKeyType())
            .setValue(key.toByteString())
            .build();
    assertThat(Registry.parseKeyData(keyData)).isEqualTo(key);
  }

  @Test
  public void testDeriveKey_succeeds() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(16).build();
    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setValue(format.toByteString())
            .setTypeUrl(new TestKeyTypeManager().getKeyType())
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    byte[] keyMaterial = Random.randBytes(100);
    KeyData keyData =  Registry.deriveKey(template, new ByteArrayInputStream(keyMaterial));
    assertThat(keyData.getKeyMaterialType()).isEqualTo(new TestKeyTypeManager().keyMaterialType());
    assertThat(keyData.getTypeUrl()).isEqualTo(new TestKeyTypeManager().getKeyType());
    AesGcmKey key =
        AesGcmKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    for (int i = 0; i < 16; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(keyMaterial[i]);
    }
  }

  // Tests that validate is called.
  @Test
  public void testDeriveKey_wrongKeySize_validateThrows() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    AesGcmKeyFormat format = AesGcmKeyFormat.newBuilder().setKeySize(32).build();
    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setValue(format.toByteString())
            .setTypeUrl(new TestKeyTypeManager().getKeyType())
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    ByteArrayInputStream emptyInput = new ByteArrayInputStream(new byte[0]);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> Registry.deriveKey(template, emptyInput));
    assertExceptionContains(e, "validateKeyFormat");
  }

  @Test
  public void testDeriveKey_inexistantKeyMananger_throws() throws Exception {
    Registry.reset();
    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setValue(AesGcmKeyFormat.getDefaultInstance().toByteString())
            .setTypeUrl(new TestKeyTypeManager().getKeyType())
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();
    ByteArrayInputStream emptyInput = new ByteArrayInputStream(new byte[0]);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> Registry.deriveKey(template, emptyInput));
    assertExceptionContains(e, "No keymanager registered");
  }

  private static class PublicPrimitiveA {}

  private static class PublicPrimitiveB {}

  private static class TestPublicKeyTypeManager extends KeyTypeManager<Ed25519PublicKey> {

    public TestPublicKeyTypeManager() {
      super(
          Ed25519PublicKey.class,
          new PrimitiveFactory<PublicPrimitiveA, Ed25519PublicKey>(PublicPrimitiveA.class) {
            @Override
            public PublicPrimitiveA getPrimitive(Ed25519PublicKey key) {
              return new PublicPrimitiveA();
            }
          },
          new PrimitiveFactory<PublicPrimitiveB, Ed25519PublicKey>(PublicPrimitiveB.class) {
            @Override
            public PublicPrimitiveB getPrimitive(Ed25519PublicKey key) {
              return new PublicPrimitiveB();
            }
          });
    }

    @Override
    public String getKeyType() {
      return "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";
    }

    @Override
    public int getVersion() {
      return 1;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.ASYMMETRIC_PUBLIC;
    }

    @Override
    public void validateKey(Ed25519PublicKey keyProto) throws GeneralSecurityException {
      if (keyProto.getKeyValue().size() != 32) {
        throw new GeneralSecurityException("validateKey(Ed25519PublicKey) failed");
      }
    }

    @Override
    public Ed25519PublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return Ed25519PublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }
  }

  private static class PrivatePrimitiveA {}

  private static class PrivatePrimitiveB {}

  private static Map<String, KeyTypeManager.KeyFactory.KeyFormat<Ed25519KeyFormat>>
      createTestEd25519KeyFormats() {
    Map<String, KeyTypeManager.KeyFactory.KeyFormat<Ed25519KeyFormat>> formats = new HashMap<>();
    formats.put(
        "TINK",
        new KeyTypeManager.KeyFactory.KeyFormat<>(
            Ed25519KeyFormat.getDefaultInstance(), KeyTemplate.OutputPrefixType.TINK));
    formats.put(
        "RAW",
        new KeyTypeManager.KeyFactory.KeyFormat<>(
            Ed25519KeyFormat.getDefaultInstance(), KeyTemplate.OutputPrefixType.RAW));
    return Collections.unmodifiableMap(formats);
  }

  private static class TestPrivateKeyTypeManager
      extends PrivateKeyTypeManager<Ed25519PrivateKey, Ed25519PublicKey> {
    public TestPrivateKeyTypeManager() {
      super(
          Ed25519PrivateKey.class,
          Ed25519PublicKey.class,
          new PrimitiveFactory<PrivatePrimitiveA, Ed25519PrivateKey>(PrivatePrimitiveA.class) {
            @Override
            public PrivatePrimitiveA getPrimitive(Ed25519PrivateKey key) {
              return new PrivatePrimitiveA();
            }
          },
          new PrimitiveFactory<PrivatePrimitiveB, Ed25519PrivateKey>(PrivatePrimitiveB.class) {
            @Override
            public PrivatePrimitiveB getPrimitive(Ed25519PrivateKey key) {
              return new PrivatePrimitiveB();
            }
          });
    }

    @Override
    public String getKeyType() {
      return "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
    }

    @Override
    public int getVersion() {
      return 1;
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      return KeyMaterialType.ASYMMETRIC_PRIVATE;
    }

    @Override
    public void validateKey(Ed25519PrivateKey keyProto) throws GeneralSecurityException {
      // Throw by hand so we can verify the exception comes from here.
      if (keyProto.getKeyValue().size() != 32) {
        throw new GeneralSecurityException("validateKey(Ed25519PrivateKey) failed");
      }
    }

    @Override
    public Ed25519PrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return Ed25519PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    @Override
    public Ed25519PublicKey getPublicKey(Ed25519PrivateKey privateKey) {
      return privateKey.getPublicKey();
    }
  }

  private static class TestPrivateKeyTypeManagerWithKeyFactory extends TestPrivateKeyTypeManager {
    private Map<String, KeyTypeManager.KeyFactory.KeyFormat<Ed25519KeyFormat>> keyFormats =
        createTestEd25519KeyFormats();

    public TestPrivateKeyTypeManagerWithKeyFactory() {
      super();
    }

    public TestPrivateKeyTypeManagerWithKeyFactory(
        Map<String, KeyTypeManager.KeyFactory.KeyFormat<Ed25519KeyFormat>> keyFormats) {
      super();
      this.keyFormats = keyFormats;
    }

    @Override
    public KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey> keyFactory() {
      return new KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey>(Ed25519KeyFormat.class) {
        @Override
        public void validateKeyFormat(Ed25519KeyFormat format) throws GeneralSecurityException {}

        @Override
        public Ed25519KeyFormat parseKeyFormat(ByteString byteString)
            throws InvalidProtocolBufferException {
          return Ed25519KeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
        }

        @Override
        public Ed25519PrivateKey createKey(Ed25519KeyFormat format)
            throws GeneralSecurityException {
          return Ed25519PrivateKey.newBuilder()
              .setKeyValue(ByteString.copyFrom("created", UTF_8))
              .build();
        }

        @Override
        public Ed25519PrivateKey deriveKey(Ed25519KeyFormat format, InputStream inputStream)
            throws GeneralSecurityException {
          return Ed25519PrivateKey.newBuilder()
              .setKeyValue(ByteString.copyFrom("derived", UTF_8))
              .build();
        }

        @Override
        public Map<String, KeyFactory.KeyFormat<Ed25519KeyFormat>> keyFormats() {
          return keyFormats;
        }
      };
    }
  }

  @Test
  public void testRegisterAssymmetricKeyManagers() throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_keyTemplates_works() throws Exception {
    Registry.reset();
    assertThat(Registry.keyTemplates()).isEmpty();

    Registry.registerKeyManager(new TestPrivateKeyTypeManagerWithKeyFactory(), true);

    assertThat(Registry.keyTemplates()).hasSize(2);
    assertThat(Registry.keyTemplates()).contains("TINK");
    assertThat(Registry.keyTemplates()).contains("RAW");
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_disallowedNewKey_keyTemplates_works()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestPrivateKeyTypeManagerWithKeyFactory(), false);
    assertThat(Registry.keyTemplates()).isEmpty();
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_existingKeyManager_noNewKeyTemplate_works()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestPrivateKeyTypeManagerWithKeyFactory(), true);
    Registry.registerKeyManager(new TestPrivateKeyTypeManagerWithKeyFactory(), true);
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_existingKeyManager_newKeyTemplate_fails()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestPrivateKeyTypeManagerWithKeyFactory(), true);

    Map<String, KeyTypeManager.KeyFactory.KeyFormat<Ed25519KeyFormat>> formats = new HashMap<>();
    formats.put(
        "NEW_KEY_TEMPLATE_NAME",
        new KeyTypeManager.KeyFactory.KeyFormat<>(
            Ed25519KeyFormat.getDefaultInstance(), KeyTemplate.OutputPrefixType.TINK));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            Registry.registerKeyManager(
                new TestPrivateKeyTypeManagerWithKeyFactory(formats), true));
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_newKeyManager_existingKeyTemplate_fails()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestPrivateKeyTypeManagerWithKeyFactory(), true);

    TestPrivateKeyTypeManagerWithKeyFactory manager =
        new TestPrivateKeyTypeManagerWithKeyFactory() {
          @Override
          public String getKeyType() {
            return "blah";
          }
        };
    assertThrows(GeneralSecurityException.class, () -> Registry.registerKeyManager(manager, true));
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_getPrivateKeyManagerPrimitiveA_works()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    KeyManager<PrivatePrimitiveA> km =
        Registry.getKeyManager(
            new TestPrivateKeyTypeManager().getKeyType(), PrivatePrimitiveA.class);
    assertThat(km.getKeyType()).isEqualTo(new TestPrivateKeyTypeManager().getKeyType());
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_getPrivateKeyManagerPrimitiveB_works()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    KeyManager<PrivatePrimitiveB> km =
        Registry.getKeyManager(
            new TestPrivateKeyTypeManager().getKeyType(), PrivatePrimitiveB.class);
    assertThat(km.getKeyType()).isEqualTo(new TestPrivateKeyTypeManager().getKeyType());
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_getPrivateKeyManagerPublicA_works()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    KeyManager<PublicPrimitiveA> km =
        Registry.getKeyManager(new TestPublicKeyTypeManager().getKeyType(), PublicPrimitiveA.class);
    assertThat(km.getKeyType()).isEqualTo(new TestPublicKeyTypeManager().getKeyType());
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_getPrivateKeyManagerPublicB_works()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    KeyManager<PublicPrimitiveB> km =
        Registry.getKeyManager(new TestPublicKeyTypeManager().getKeyType(), PublicPrimitiveB.class);
    assertThat(km.getKeyType()).isEqualTo(new TestPublicKeyTypeManager().getKeyType());
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_getPrivateKeyManagerWrongPrimitive_throws()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Registry.getKeyManager(new TestPrivateKeyTypeManager().getKeyType(), Mac.class));
    assertExceptionContains(e, "com.google.crypto.tink.Mac");
    assertExceptionContains(e, "PrivatePrimitiveA");
      assertExceptionContains(e, "PrivatePrimitiveB");
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_getPublicKeyManagerWrongPrimitive_throws()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Registry.getKeyManager(new TestPublicKeyTypeManager().getKeyType(), Mac.class));
    assertExceptionContains(e, "com.google.crypto.tink.Mac");
    assertExceptionContains(e, "PublicPrimitiveA");
      assertExceptionContains(e, "PublicPrimitiveB");
  }

  // Checks that calling getUntypedKeyManager will return the keymanager for the *first* implemented
  // class in the constructor.
  @Test
  public void testRegisterAssymmetricKeyManagers_getUntypedPrivateKeyManager_returnsPrimitiveA()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    KeyManager<?> km = Registry.getUntypedKeyManager(new TestPrivateKeyTypeManager().getKeyType());
    assertThat(km.getPrimitiveClass()).isEqualTo(PrivatePrimitiveA.class);
  }

  // Checks that calling getUntypedKeyManager will return the keymanager for the *first* implemented
  // class in the constructor.
  @Test
  public void testRegisterAssymmetricKeyManagers_getUntypedPublicKeyManager_returnsPrimitiveA()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    KeyManager<?> km = Registry.getUntypedKeyManager(new TestPublicKeyTypeManager().getKeyType());
    assertThat(km.getPrimitiveClass()).isEqualTo(PublicPrimitiveA.class);
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_newKeyAllowed_withoutKeyFactory_fails()
      throws Exception {
    Registry.reset();
    assertThrows(
        UnsupportedOperationException.class,
        () ->
            Registry.registerAsymmetricKeyManagers(
                new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), true));
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_moreRestrictedNewKeyAllowed_shouldWork()
      throws Exception {
    Registry.reset();

    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), true);
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), false);
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_sameNewKeyAllowed_shouldWork() throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), true);
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), true);
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), false);
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), false);
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_lessRestrictedNewKeyAllowed_throws()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), false);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            Registry.registerAsymmetricKeyManagers(
                new TestPrivateKeyTypeManagerWithKeyFactory(),
                new TestPublicKeyTypeManager(),
                true));
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_publicKeyManagerCanBeRegisteredAlone()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestPublicKeyTypeManager(), false);
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), true);
    Registry.registerKeyManager(new TestPublicKeyTypeManager(), false);
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_publicKeyManagerReRegister_getPublicKeyData()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestPublicKeyTypeManager(), false);
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    Registry.registerKeyManager(new TestPublicKeyTypeManager(), false);

    // Check that getPublicKeyData works now.
    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setPublicKey(
                Ed25519PublicKey.newBuilder()
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(32))))
            .build();
    KeyData publicKeyData =
        Registry.getPublicKeyData(
            new TestPrivateKeyTypeManager().getKeyType(), privateKey.toByteString());
    assertThat(publicKeyData.getTypeUrl()).isEqualTo(new TestPublicKeyTypeManager().getKeyType());
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.parseFrom(
            publicKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(publicKey.getKeyValue()).isEqualTo(privateKey.getPublicKey().getKeyValue());
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_differentClassPrivateKey_throws()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            Registry.registerAsymmetricKeyManagers(
                new TestPrivateKeyTypeManager() {}, new TestPublicKeyTypeManager(), false));
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_differentClassPublicKey_throws() throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            Registry.registerAsymmetricKeyManagers(
                // Note: due to the {} this is a subclass of TestPublicKeyTypeManager.
                new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager() {}, false));
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_thenNormalRegister_throws()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    assertThrows(
        GeneralSecurityException.class,
        // Note: due to the {} this is a subclass of TestPublicKeyTypeManager.
        () -> Registry.registerKeyManager(new TestPrivateKeyTypeManager() {}, false));
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_thenNormalRegisterForPublic_throws()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    assertThrows(
        GeneralSecurityException.class,
        // Note: due to the {} this is a subclass of TestPublicKeyTypeManager.
        () -> Registry.registerKeyManager(new TestPublicKeyTypeManager() {}, false));
  }

  @Test
  public void testRegisterAssymmetricKeyManagers_throwsWithDifferentPublicKeyManager()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                Registry.registerAsymmetricKeyManagers(
                    new TestPrivateKeyTypeManager(),
                    new TestPublicKeyTypeManager() {
                      @Override
                      public String getKeyType() {
                        return "bla";
                      }
                    },
                    false));
    assertExceptionContains(e, "public key manager corresponding to");
  }

  @Test
  public void testAsymmetricKeyManagers_deriveKey_withoutKeyFactory() throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setValue(Ed25519KeyFormat.getDefaultInstance().toByteString())
            .setTypeUrl(new TestPrivateKeyTypeManager().getKeyType())
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    assertThrows(
        UnsupportedOperationException.class,
        () -> Registry.deriveKey(template, new ByteArrayInputStream(new byte[0])));
  }

  @Test
  public void testAsymmetricKeyManagers_deriveKey() throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManagerWithKeyFactory(), new TestPublicKeyTypeManager(), true);
    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.newBuilder()
            .setValue(Ed25519KeyFormat.getDefaultInstance().toByteString())
            .setTypeUrl(new TestPrivateKeyTypeManagerWithKeyFactory().getKeyType())
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build();

    KeyData keyData =  Registry.deriveKey(template, new ByteArrayInputStream(new byte[0]));
    Ed25519PrivateKey key =
        Ed25519PrivateKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(key.getKeyValue()).isEqualTo(ByteString.copyFrom("derived", UTF_8));
  }

  private static class Catalogue1 implements Catalogue<Aead> {
    @Override
    public KeyManager<Aead> getKeyManager(String typeUrl, String primitiveName, int minVersion) {
      return null;
    }

    @Override
    public PrimitiveWrapper<Aead, Aead> getPrimitiveWrapper() {
      return null;
    }
  }

  private static class Catalogue2 implements Catalogue<Aead> {
    @Override
    public KeyManager<Aead> getKeyManager(String typeUrl, String primitiveName, int minVersion) {
      return null;
    }

    @Override
    public PrimitiveWrapper<Aead, Aead> getPrimitiveWrapper() {
      return null;
    }
  }

  private static class Catalogue3 implements Catalogue<Aead> {
    @Override
    public KeyManager<Aead> getKeyManager(String typeUrl, String primitiveName, int minVersion) {
      return null;
    }

    @Override
    public PrimitiveWrapper<Aead, Aead> getPrimitiveWrapper() {
      return null;
    }
  }

  @Test
  public void testAddCatalogue_multiThreads_shouldWork() throws Exception {
    final boolean[] threwException = new boolean[3];
    Thread thread1 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                try {
                  Registry.addCatalogue("catalogue", new Catalogue1());
                  threwException[0] = false;
                } catch (GeneralSecurityException e) {
                  threwException[0] = true;
                }
              }
            });
    Thread thread2 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                try {
                  Registry.addCatalogue("catalogue", new Catalogue2());
                  threwException[1] = false;
                } catch (GeneralSecurityException e) {
                  threwException[1] = true;
                }
              }
            });
    Thread thread3 =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                try {
                  Registry.addCatalogue("catalogue", new Catalogue3());
                  threwException[2] = false;
                } catch (GeneralSecurityException e) {
                  threwException[2] = true;
                }
              }
            });

    // Start the threads.
    thread1.start();
    thread2.start();
    thread3.start();

    // Wait until all threads finished.
    thread1.join();
    thread2.join();
    thread3.join();

    // Count threads that threw exception.
    int count = 0;
    for (int i = 0; i < 3; i++) {
      if (threwException[i]) {
        count++;
      }
    }

    assertThat(count).isEqualTo(2);
  }
  // TODO(przydatek): Add more tests for creation of PrimitiveSets.

  private static PrimitiveSet<Aead> createAeadPrimitiveSet() throws Exception {
    return TestUtil.createPrimitiveSet(
        TestUtil.createKeyset(
            Keyset.Key.newBuilder()
                .setKeyData(Registry.newKeyData(AesEaxKeyManager.aes128EaxTemplate()))
                .setKeyId(1)
                .setStatus(KeyStatusType.ENABLED)
                .setOutputPrefixType(OutputPrefixType.TINK)
                .build()),
        Aead.class);
  }

  @Test
  public void testWrap_wrapperRegistered() throws Exception {
    Registry.wrap(createAeadPrimitiveSet());
  }

  @Test
  public void testWrap_noWrapperRegistered_throws() throws Exception {
    PrimitiveSet<Aead> aeadSet = createAeadPrimitiveSet();
    Registry.reset();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Registry.wrap(aeadSet));
    assertExceptionContains(e, "No wrapper found");
    assertExceptionContains(e, "Aead");
  }

  @Test
  public void testWrap_wrapAsEncryptOnly() throws Exception {
    // Check that Registry.wrap can be assigned to an EncryptOnly (as there's a suppress warning).
    EncryptOnly encrypt = Registry.wrap(createAeadPrimitiveSet(), EncryptOnly.class);
    assertThat(encrypt).isNotNull();
  }

  @Test
  public void testWrap_registerSecondWrapperForEncryptOnly_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> {
          Registry.registerPrimitiveWrapper(
              new PrimitiveWrapper<Mac, EncryptOnly>() {
                @Override
                public EncryptOnly wrap(PrimitiveSet<Mac> primitiveSet) {
                  return null;
                }

                @Override
                public Class<EncryptOnly> getPrimitiveClass() {
                  return EncryptOnly.class;
                }

                @Override
                public Class<Mac> getInputPrimitiveClass() {
                  return Mac.class;
                }
              });
        });
  }

  @Test
  public void testFips_succeedsOnEmptyRegistry() throws Exception {
    Registry.reset();
    Registry.restrictToFipsIfEmpty();
    assertTrue(TinkFipsUtil.useOnlyFips());
  }

  @Test
  public void testFips_failsOnNonEmptyRegistry() throws Exception {
    assertThrows(GeneralSecurityException.class, Registry::restrictToFipsIfEmpty);
  }

  @Test
  public void testFips_registerNonFipsKeyTypeManagerFails() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    Registry.reset();
    Registry.restrictToFipsIfEmpty();

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new TestKeyTypeManager(), true));
  }


  @Test
  public void testFips_registerFipsKeyTypeManagerSucceeds() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    Registry.reset();
    Registry.restrictToFipsIfEmpty();
    AesGcmKeyManager.register(true);
  }

  @Test
  public void testFips_registerNonFipsKeyTypeManagerAsymmetricFails() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    Registry.reset();
    Registry.restrictToFipsIfEmpty();

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false));
  }


  @Test
  public void testFips_registerFipsKeyTypeManagerAsymmetricSucceeds() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    Registry.reset();
    Registry.restrictToFipsIfEmpty();

    EcdsaSignKeyManager.registerPair(true);
  }

  private static class FakeAead {}
}
