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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.jwt.JwtMac;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.PredefinedMacParameters;
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
import java.security.GeneralSecurityException;
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
    public static final AeadToEncryptOnlyWrapper WRAPPER = new AeadToEncryptOnlyWrapper();

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
    // All tests for the registry assume that if the tests are run in FIPS, that BoringSSL is
    // built in FIPS mode. If BoringSSL is not built in FIPS mode, there aren't any key managers
    // available which could be registered, therefore the tests would just fail.
    Assume.assumeFalse(TinkFips.useOnlyFips() && !TinkFipsUtil.fipsModuleAvailable());

    TinkFipsUtil.unsetFipsRestricted();
    Registry.reset();
    TinkConfig.register();
    Registry.registerPrimitiveWrapper(AeadToEncryptOnlyWrapper.WRAPPER);
  }

  private void testGetKeyManagerShouldWork(String typeUrl, String className) throws Exception {
    assertThat(Registry.getUntypedKeyManager(typeUrl).getClass().toString()).contains(className);
  }

  @Test
  public void testGetKeyManager_legacy_shouldWork() throws Exception {
    // Skip test if in FIPS mode, as EAX is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    testGetKeyManagerShouldWork(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL, "KeyManagerImpl");
    testGetKeyManagerShouldWork(AeadConfig.AES_EAX_TYPE_URL, "KeyManagerImpl");
    testGetKeyManagerShouldWork(MacConfig.HMAC_TYPE_URL, "KeyManagerImpl");
  }

  @Test
  public void testGetKeyManager_shouldWorkAesEax() throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
        assertThrows(
            GeneralSecurityException.class, () -> Registry.getUntypedKeyManager(badTypeUrl));
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
  public void testRegisterKeyManager_primitiveIsUnknown_shouldThrowException() throws Exception {
    KeyManager<JwtMac> unknownPrimitiveKeyManager =
        new KeyManager<JwtMac>() {
          @Override
          public JwtMac getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
            throw new UnsupportedOperationException();
          }

          /**
           * Returns the type URL that identifies the key type of keys managed by this KeyManager.
           */
          @Override
          public String getKeyType() {
            return "someKeyType";
          }

          @Override
          public Class<JwtMac> getPrimitiveClass() {
            return JwtMac.class;
          }

          @Override
          public KeyData newKeyData(ByteString serializedKeyFormat)
              throws GeneralSecurityException {
            throw new UnsupportedOperationException();
          }
        };

    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> Registry.registerKeyManager(unknownPrimitiveKeyManager));
    assertThat(e.toString()).contains("Registration of key managers for class");
  }

  @Test
  public void testRegisterKeyManager_moreRestrictedNewKeyAllowed_shouldWork() throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    String typeUrl = "someTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl));
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), false);
  }

  @Test
  public void testRegisterKeyManager_sameNewKeyAllowed_shouldWork() throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    String typeUrl = "someOtherTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl));
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), true);
  }

  @Test
  public void testRegisterKeyManager_lessRestrictedNewKeyAllowed_shouldThrowException()
      throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    String typeUrl = "yetAnotherTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), false);

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), true));
  }

  @Test
  public void testRegisterKeyManager_keyManagerFromAnotherClass_shouldThrowException()
      throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    // This should not overwrite the existing manager.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                Registry.registerKeyManager(
                    new CustomAeadKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL)));
    assertThat(e.toString()).contains("already registered");

    KeyManager<?> manager = Registry.getUntypedKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL);
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
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    String typeUrl = "totallyDifferentTypeUrl";
    Registry.registerKeyManager(typeUrl, new CustomAeadKeyManager(typeUrl), false);

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(typeUrl, new CustomAeadKeyManager(typeUrl), true));
  }

  @Test
  public void testRegisterKeyManager_deprecated_keyManagerFromAnotherClass_shouldThrowException()
      throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    // This should not overwrite the existing manager.
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                Registry.registerKeyManager(
                    AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL,
                    new CustomAeadKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL)));
    assertThat(e.toString()).contains("already registered");

    KeyManager<?> manager = Registry.getUntypedKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL);
    assertThat(manager.getClass().toString()).contains("KeyManagerImpl");
  }

  @Test
  public void testGetPublicKeyData_shouldWork() throws Exception {
    // Skip test if in FIPS mode, as no provider available to instantiate.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    KeyData privateKeyData = Registry.newKeyData(SignatureKeyTemplates.ECDSA_P256);
    KeyData publicKeyData = Registry.getPublicKeyData(privateKeyData.getTypeUrl(),
        privateKeyData.getValue());
    PublicKeyVerify verifier = Registry.getPrimitive(publicKeyData, PublicKeyVerify.class);
    PublicKeySign signer = Registry.getPrimitive(privateKeyData, PublicKeySign.class);
    byte[] message = "Nice test message".getBytes(UTF_8);
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void testGetPublicKeyData_shouldThrow() throws Exception {
    KeyData keyData =
        Registry.newKeyData(
            com.google.crypto.tink.proto.KeyTemplate.parseFrom(
                TinkProtoParametersFormat.serialize(PredefinedMacParameters.HMAC_SHA256_128BITTAG),
                ExtensionRegistryLite.getEmptyRegistry()));
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
  public void testGetPrimitive_aesGcm_shouldWork() throws Exception {
    // Skip test if in FIPS mode, as EAX is not supported in FIPS mode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
  public void testGetPrimitive_hmac_shouldWork() throws Exception {
    // Skip test if in FIPS mode, as no provider available to instantiate.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    com.google.crypto.tink.proto.KeyTemplate template =
        com.google.crypto.tink.proto.KeyTemplate.parseFrom(
            TinkProtoParametersFormat.serialize(PredefinedMacParameters.HMAC_SHA256_128BITTAG),
            ExtensionRegistryLite.getEmptyRegistry());
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
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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

  /** Implementation of a KeyTypeManager for testing. */
  private static class TestKeyTypeManager extends KeyTypeManager<AesGcmKey> {

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

    public TestKeyTypeManager(Map<String, Parameters> namedParameters) {
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
      };
    }

    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    }
  }

  // Same as TestKeyTypeManager, but not compatible with FIPS.
  private static class TestKeyTypeManagerNonFips extends TestKeyTypeManager {
    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
    }
  }

  @Test
  public void testRegisterKeyTypeManager() throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
  }

  @Test
  public void testRegisterKeyTypeManager_existingKeyManager_noNewKeyTemplate_works()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
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
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), false);
    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new TestKeyTypeManager(), true));
  }

  @Test
  public void testRegisterKeyTypeManager_differentClass_throws() throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    Registry.reset();
    Registry.registerKeyManager(new TestKeyTypeManager(), true);
    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new TestKeyTypeManager() {}, true));
  }

  @Test
  public void testRegisterKeyTypeManager_afterKeyManager_throws() throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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

    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    }
  }

  // Same as TestPublicKeyTypeManager, but not compatible with FIPS.
  private static class TestPublicKeyTypeManagerNonFips extends TestPublicKeyTypeManager {
    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
    }
  }

  private static class PrivatePrimitiveA {}

  private static class PrivatePrimitiveB {}

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

    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    }
  }

  // Same as TestPrivateKeyTypeManager, but not compatible with FIPS.
  private static class TestPrivateKeyTypeManagerNonFips extends TestPrivateKeyTypeManager {
    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
    }
  }

  private static class TestPrivateKeyTypeManagerWithKeyFactory extends TestPrivateKeyTypeManager {

    public TestPrivateKeyTypeManagerWithKeyFactory() {
      super();
    }

    @Override
    public KeyTypeManager.KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey> keyFactory() {
      return new KeyTypeManager.KeyFactory<Ed25519KeyFormat, Ed25519PrivateKey>(
          Ed25519KeyFormat.class) {
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
  public void testRegisterAssymmetricKeyManagers_existingKeyManager_noNewKeyTemplate_works()
      throws Exception {
    Registry.reset();
    Registry.registerKeyManager(new TestPrivateKeyTypeManagerWithKeyFactory(), true);
    Registry.registerKeyManager(new TestPrivateKeyTypeManagerWithKeyFactory(), true);
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
  public void testRegisterAssymmetricKeyManagers_getPublicKeyData_shouldWork()
      throws Exception {
    Registry.reset();
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);

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
  public void testRegisterAsymmetricKeyManagersSeparately_getPublicKeyData_throws()
      throws Exception {
    Registry.reset();
    // Register asymmetric key managers only with registerKeyManager.
    Registry.registerKeyManager(new TestPrivateKeyTypeManager(), false);
    Registry.registerKeyManager(new TestPublicKeyTypeManager(), false);

    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setPublicKey(
                Ed25519PublicKey.newBuilder()
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(32))))
            .build();
    assertThrows(
        GeneralSecurityException.class,
        () ->
            Registry.getPublicKeyData(
            new TestPrivateKeyTypeManager().getKeyType(), privateKey.toByteString()));
  }

  @Test
  public void testRegisterAssymmetricKeyManagersOnce_getPublicKeyData_shouldWork()
      throws Exception {
    Registry.reset();
    // Register asymmetric key managers with registerAsymmetricKeyManagers and registerKeyManager.
    Registry.registerKeyManager(new TestPrivateKeyTypeManager(), false);
    Registry.registerKeyManager(new TestPublicKeyTypeManager(), false);
    Registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager(), new TestPublicKeyTypeManager(), false);
    Registry.registerKeyManager(new TestPrivateKeyTypeManager(), false);
    Registry.registerKeyManager(new TestPublicKeyTypeManager(), false);

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
                // Note: due to the {} this is a subclass of TestPrivateKeyTypeManager.
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
    // Skip test if in FIPS mode, as EAX is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    assertNotNull(Registry.wrap(createAeadPrimitiveSet()));
  }

  @Test
  public void testWrap_noWrapperRegistered_throws() throws Exception {
    // Skip test if in FIPS mode, as EAX is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

    PrimitiveSet<Aead> aeadSet = createAeadPrimitiveSet();
    Registry.reset();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> Registry.wrap(aeadSet));
    assertExceptionContains(e, "No wrapper found");
    assertExceptionContains(e, "Aead");
  }

  @Test
  public void testWrap_wrapAsEncryptOnly() throws Exception {
    // Skip test if in FIPS mode, as EAX is not allowed in FipsMode.
    Assume.assumeFalse(TinkFips.useOnlyFips());

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
  public void testRestrictToFips_fipsModuleAvailable_succeedsOnEmptyRegistry() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());
    Registry.reset();
    Registry.restrictToFipsIfEmpty();
    assertTrue(TinkFipsUtil.useOnlyFips());
  }

  @Test
  public void test_fipsModuleNotAvailable_fails() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.fipsModuleAvailable());
    Registry.reset();
    assertThrows(GeneralSecurityException.class, Registry::restrictToFipsIfEmpty);
  }

  @Test
  public void testSuccessiveRestrictToFips_works() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());
    Registry.reset();
    Registry.restrictToFipsIfEmpty();
    Registry.restrictToFipsIfEmpty();
    Registry.restrictToFipsIfEmpty();
    assertTrue(TinkFipsUtil.useOnlyFips());
  }

  @Test
  public void testRestrictToFips_builtInFipsMode_works() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.useOnlyFips());
    Registry.restrictToFipsIfEmpty();
    assertTrue(TinkFipsUtil.useOnlyFips());
  }

  @Test
  public void testRestrictToFips_failsOnNonEmptyRegistry() throws Exception {
    Assume.assumeFalse(TinkFipsUtil.useOnlyFips());
    assertThrows(GeneralSecurityException.class, Registry::restrictToFipsIfEmpty);
  }

  @Test
  public void testFips_registerNonFipsKeyTypeManagerFails() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    Registry.reset();
    Registry.restrictToFipsIfEmpty();

    assertThrows(
        GeneralSecurityException.class,
        () -> Registry.registerKeyManager(new TestKeyTypeManagerNonFips(), true));
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
        () ->
            Registry.registerAsymmetricKeyManagers(
                new TestPrivateKeyTypeManagerNonFips(),
                new TestPublicKeyTypeManagerNonFips(),
                false));
  }


  @Test
  public void testFips_registerFipsKeyTypeManagerAsymmetricSucceeds() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    Registry.reset();
    Registry.restrictToFipsIfEmpty();

    EcdsaSignKeyManager.registerPair(true);
  }


  @Test
  public void testFips_registerFipsKeyManager_fails() throws Exception {
    Assume.assumeTrue(TinkFipsUtil.fipsModuleAvailable());

    Registry.reset();
    Registry.restrictToFipsIfEmpty();

    String typeUrl = "testNewKeyDataTypeUrl";
    CustomAeadKeyManager km = new CustomAeadKeyManager(typeUrl);
    assertThrows(
        GeneralSecurityException.class, () -> Registry.registerKeyManager(km));
  }

  private static class FakeAead {}
}
