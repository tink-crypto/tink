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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeyManagerRegistry}. */
@RunWith(JUnit4.class)
public final class KeyManagerRegistryTest {
  private static class Primitive1 {}

  private static class Primitive2 {}

  private static class TestKeyManager implements KeyManager<Primitive1> {
    public TestKeyManager(String typeUrl) {
      this.typeUrl = typeUrl;
    }

    private final String typeUrl;

    @Override
    public Primitive1 getPrimitive(ByteString proto) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public Primitive1 getPrimitive(MessageLite proto) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public MessageLite newKey(ByteString template) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public MessageLite newKey(MessageLite template) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public boolean doesSupport(String typeUrl) {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public String getKeyType() {
      return this.typeUrl;
    }

    @Override
    public int getVersion() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public Class<Primitive1> getPrimitiveClass() {
      return Primitive1.class;
    }
  }

  private static class TestKeyTypeManager extends KeyTypeManager<AesGcmKey> {
    private final String typeUrl;

    public TestKeyTypeManager(String typeUrl) {
      super(
          AesGcmKey.class,
          new PrimitiveFactory<Primitive1, AesGcmKey>(Primitive1.class) {
            @Override
            public Primitive1 getPrimitive(AesGcmKey key) {
              return new Primitive1();
            }
          },
          new PrimitiveFactory<Primitive2, AesGcmKey>(Primitive2.class) {
            @Override
            public Primitive2 getPrimitive(AesGcmKey key) {
              return new Primitive2();
            }
          });
      this.typeUrl = typeUrl;
    }

    @Override
    public String getKeyType() {
      return typeUrl;
    }

    @Override
    public int getVersion() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public KeyMaterialType keyMaterialType() {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public void validateKey(AesGcmKey keyProto) throws GeneralSecurityException {}

    @Override
    public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return AesGcmKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    /* We set the key manager FIPS compatible per default, such that all tests which use key
     * managers can also be run if Tink.useOnlyFips() == true.*/
    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    }
  }

  @Test
  public void testEmptyRegistry() throws Exception {
    KeyManagerRegistry registry = new KeyManagerRegistry();
    assertThrows(
        GeneralSecurityException.class, () -> registry.getKeyManager("customTypeUrl", Aead.class));
    assertThrows(GeneralSecurityException.class, () -> registry.getKeyManager("customTypeUrl"));
    assertThrows(
        GeneralSecurityException.class, () -> registry.getUntypedKeyManager("customTypeUrl"));
    assertThat(registry.typeUrlExists("customTypeUrl")).isFalse();
  }

  @Test
  public void testRegisterKeyManager_works() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager = new TestKeyManager("customTypeUrl");
    registry.registerKeyManager(manager);

    assertThat(registry.getKeyManager("customTypeUrl", Primitive1.class)).isSameInstanceAs(manager);
    assertThat(registry.typeUrlExists("customTypeUrl")).isTrue();
  }

  @Test
  public void testRegisterKeyManager_twice_works() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager1 = new TestKeyManager("customTypeUrl");
    TestKeyManager manager2 = new TestKeyManager("customTypeUrl");
    registry.registerKeyManager(manager1);
    registry.registerKeyManager(manager2);

    assertThat(registry.getKeyManager("customTypeUrl", Primitive1.class))
        .isAnyOf(manager1, manager2);
  }

  @Test
  public void testRegisterKeyManager_differentManagersSameKeyType_fails() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerKeyManager(new TestKeyManager("customTypeUrl"));
    // Adding {} at the end makes this an anonymous subclass, hence a different class, so this
    // throws.
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.registerKeyManager(new TestKeyManager("customTypeUrl") {}));
  }

  @Test
  public void testRegisterKeyManager_twoKeyTypes_works() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager1 = new TestKeyManager("customTypeUrl1");
    TestKeyManager manager2 = new TestKeyManager("customTypeUrl2");
    registry.registerKeyManager(manager1);
    registry.registerKeyManager(manager2);
    assertThat(registry.getKeyManager("customTypeUrl1", Primitive1.class))
        .isSameInstanceAs(manager1);
    assertThat(registry.getKeyManager("customTypeUrl2", Primitive1.class))
        .isSameInstanceAs(manager2);
  }

  @Test
  public void testRegisterKeyTypeManager_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    KeyTypeManager<AesGcmKey> manager = new TestKeyTypeManager("customTypeUrl1");
    assertThrows(
        GeneralSecurityException.class, () -> registry.getUntypedKeyManager("customTypeUrl1"));
    registry.registerKeyManager(manager);
    assertThat(registry.getUntypedKeyManager("customTypeUrl1")).isNotNull();
  }

  @Test
  public void testRegisterKeyTypeManager_twice_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    KeyTypeManager<AesGcmKey> manager1 = new TestKeyTypeManager("customTypeUrl1");
    KeyTypeManager<AesGcmKey> manager2 = new TestKeyTypeManager("customTypeUrl1");
    registry.registerKeyManager(manager1);
    registry.registerKeyManager(manager2);
  }

  @Test
  public void testRegisterKeyManagerAndKeyTypeManager_fails() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    // After a registered KeyTypeManager, the KeyManager registering fails.
    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerKeyManager(new TestKeyTypeManager("customTypeUrl1"));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.registerKeyManager(new TestKeyManager("customTypeUrl1")));

    // After a registered KeyManager, the KeyTypeManager registering fails.
    KeyManagerRegistry registry2 = new KeyManagerRegistry();
    registry2.registerKeyManager(new TestKeyManager("customTypeUrl1"));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry2.registerKeyManager(new TestKeyTypeManager("customTypeUrl1")));
  }

  @Test
  public void testTypeUrlExists() throws Exception {
    assumeFalse("Unable to test with KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager1 = new TestKeyManager("customTypeUrl1");
    TestKeyManager manager2 = new TestKeyManager("customTypeUrl2");
    registry.registerKeyManager(manager1);
    registry.registerKeyManager(manager2);
    assertThat(registry.typeUrlExists("customTypeUrl1")).isTrue();
    assertThat(registry.typeUrlExists("customTypeUrl2")).isTrue();
    assertThat(registry.typeUrlExists("unknownTypeUrl")).isFalse();
  }

  @Test
  public void testTypeUrlExists_keyTypeManagers() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyTypeManager manager1 = new TestKeyTypeManager("customTypeUrl1");
    TestKeyTypeManager manager2 = new TestKeyTypeManager("customTypeUrl2");
    registry.registerKeyManager(manager1);
    registry.registerKeyManager(manager2);
    assertThat(registry.typeUrlExists("customTypeUrl1")).isTrue();
    assertThat(registry.typeUrlExists("customTypeUrl2")).isTrue();
    assertThat(registry.typeUrlExists("unknownTypeUrl")).isFalse();
  }

  @Test
  public void testGetKeyManager_works() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    KeyManager<?> registered = new TestKeyManager("typeUrl");
    registry.registerKeyManager(registered);
    KeyManager<Primitive1> aeadManager1 = registry.getKeyManager("typeUrl", Primitive1.class);
    KeyManager<Primitive1> aeadManager2 = registry.getKeyManager("typeUrl");
    KeyManager<?> manager = registry.getUntypedKeyManager("typeUrl");
    assertThat(aeadManager1).isSameInstanceAs(registered);
    assertThat(aeadManager2).isSameInstanceAs(registered);
    assertThat(manager).isSameInstanceAs(registered);
  }

  // The method "parseKeyData" only works if a KeyTypeManager was registered -- KeyManager objects
  // do not support this.
  @Test
  public void testParseKeyData_keyTypeManager_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerKeyManager(new TestKeyTypeManager("typeUrl"));
    AesGcmKey key = AesGcmKey.newBuilder().setVersion(13).build();
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl("typeUrl")
            .setValue(key.toByteString())
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .build();
    assertThat(registry.parseKeyData(keyData)).isEqualTo(key);
  }

  @Test
  public void testParseKeyData_keyManager_returnsNull() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerKeyManager(new TestKeyManager("typeUrl"));
    AesGcmKey key = AesGcmKey.newBuilder().setVersion(13).build();
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl("typeUrl")
            .setValue(key.toByteString())
            .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
            .build();
    assertThat(registry.parseKeyData(keyData)).isNull();
  }

  private static class TestPublicKeyTypeManager extends KeyTypeManager<Ed25519PublicKey> {
    private final String typeUrl;

    public TestPublicKeyTypeManager(String typeUrl) {
      super(Ed25519PublicKey.class);
      this.typeUrl = typeUrl;
    }

    @Override
    public String getKeyType() {
      return typeUrl;
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
      // The point of registering both key managers at once is that when we get the public key
      // from the privateKeyManager, the registry validates the key proto here. We check this call
      // happens by throwing here.
      if (keyProto.getVersion() != 1) {
        throw new GeneralSecurityException("PublicKeyManagerValidationIsInvoked");
      }
    }

    @Override
    public Ed25519PublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {

      return Ed25519PublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    /* We set the key manager FIPS compatible per default, such that all tests which use key
     * managers can also be run if Tink.useOnlyFips() == true.*/
    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    }
  }

  private static class TestPrivateKeyTypeManager
      extends PrivateKeyTypeManager<Ed25519PrivateKey, Ed25519PublicKey> {
    private final String typeUrl;

    public TestPrivateKeyTypeManager(String typeUrl) {
      super(Ed25519PrivateKey.class, Ed25519PublicKey.class);
      this.typeUrl = typeUrl;
    }

    @Override
    public String getKeyType() {
      return typeUrl;
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
    public void validateKey(Ed25519PrivateKey keyProto) throws GeneralSecurityException {}

    @Override
    public Ed25519PrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
      return Ed25519PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    }

    @Override
    public Ed25519PublicKey getPublicKey(Ed25519PrivateKey privateKey) {
      return privateKey.getPublicKey();
    }

    /* We set the key manager FIPS compatible per default, such that all tests which use key
     * managers can also be run if Tink.useOnlyFips() == true.*/
    @Override
    public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
      return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    }
  }

  @Test
  public void testRegisterAsymmetricKeyManager_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }
    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager("privateTypeUrl"),
        new TestPublicKeyTypeManager("publicTypeUrl"));

    assertThat(registry.getUntypedKeyManager("privateTypeUrl")).isNotNull();
    assertThat(registry.getUntypedKeyManager("publicTypeUrl")).isNotNull();
  }

  @Test
  public void testRegisterAsymmetricKeyManagerTwice_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager("privateTypeUrl"),
        new TestPublicKeyTypeManager("publicTypeUrl"));
    registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager("privateTypeUrl"),
        new TestPublicKeyTypeManager("publicTypeUrl"));
    assertThat(registry.getUntypedKeyManager("privateTypeUrl")).isNotNull();
    assertThat(registry.getUntypedKeyManager("publicTypeUrl")).isNotNull();
  }

  @Test
  public void testRegisterDifferentAsymmetricKeyManagerForTheSameKeyTypeUrl_throws()
      throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager("privateTypeUrl"),
        new TestPublicKeyTypeManager("publicTypeUrl"));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.registerAsymmetricKeyManagers(
                // Note: due to the {} this is a subclass of TestPrivateKeyTypeManager.
                new TestPrivateKeyTypeManager("privateTypeUrl") {},
                new TestPublicKeyTypeManager("publicTypeUrl")));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.registerAsymmetricKeyManagers(
                new TestPrivateKeyTypeManager("privateTypeUrl"),
                // Note: due to the {} this is a subclass of TestPublicKeyTypeManager.
                new TestPublicKeyTypeManager("publicTypeUrl") {}));
  }

  @Test
  public void testRegisterAsymmetricKeyManager_thenSymmetricDifferentType_throws()
      throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager("privateTypeUrl"),
        new TestPublicKeyTypeManager("publicTypeUrl"));
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.registerKeyManager(new TestKeyTypeManager("privateTypeUrl")));
  }

  @Test
  public void testAsymmetricKeyManagers_getPublicKey_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestPrivateKeyTypeManager privateKeyTypeManager =
        new TestPrivateKeyTypeManager("privateTypeUrl");
    TestPublicKeyTypeManager publicKeyTypeManager = new TestPublicKeyTypeManager("publicTypeUrl");
    registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager);
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.newBuilder()
            .setVersion(1)
            .setKeyValue(ByteString.copyFrom(new byte[] {0, 1, 2, 3}))
            .build();
    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder().setPublicKey(publicKey).setVersion(1).build();
    KeyData publicKeyData =
        ((PrivateKeyManager) registry.getUntypedKeyManager("privateTypeUrl"))
            .getPublicKeyData(privateKey.toByteString());
    Ed25519PublicKey parsedPublicKey =
        Ed25519PublicKey.parseFrom(
            publicKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(parsedPublicKey).isEqualTo(publicKey);
  }

  /**
   * The point of registering Asymmetric KeyManagers together is that the public key validation
   * method is invoked when we get a public key from a private key. Here we verify that this
   * happens.
   */
  @Test
  public void testAsymmetricKeyManagers_getPublicKey_validationIsInvoked_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestPrivateKeyTypeManager privateKeyTypeManager =
        new TestPrivateKeyTypeManager("privateTypeUrl");
    TestPublicKeyTypeManager publicKeyTypeManager = new TestPublicKeyTypeManager("publicTypeUrl");
    registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager);
    // Version 0 will make sure that we get a validation error thrown
    Ed25519PublicKey publicKey = Ed25519PublicKey.newBuilder().setVersion(0).build();
    ByteString serializedPrivateKey =
        Ed25519PrivateKey.newBuilder().setPublicKey(publicKey).setVersion(1).build().toByteString();
    PrivateKeyManager<?> privateKeyManager =
        (PrivateKeyManager) registry.getUntypedKeyManager("privateTypeUrl");
    GeneralSecurityException thrown =
        assertThrows(
            GeneralSecurityException.class,
            () -> privateKeyManager.getPublicKeyData(serializedPrivateKey));
    assertThat(thrown).hasMessageThat().contains("PublicKeyManagerValidationIsInvoked");
  }

  @Test
  public void testAsymmetricKeyManagers_doubleRegistration_classChange_throws() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestPrivateKeyTypeManager privateKeyTypeManager =
        new TestPrivateKeyTypeManager("privateTypeUrl");
    TestPublicKeyTypeManager publicKeyTypeManager1 = new TestPublicKeyTypeManager("publicTypeUrl");
    // Add parentheses to make sure it's a different class which implements the manager.
    TestPublicKeyTypeManager publicKeyTypeManager2 =
        new TestPublicKeyTypeManager("publicTypeUrl") {};
    registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager1);
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager2));
  }

  /** One is allowed to sometimes register asymmetric key managers without their counterpart. */
  @Test
  public void testAsymmetricKeyManagers_registerOnceWithThenWithout_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestPrivateKeyTypeManager privateKeyTypeManager =
        new TestPrivateKeyTypeManager("privateTypeUrl");
    TestPublicKeyTypeManager publicKeyTypeManager = new TestPublicKeyTypeManager("publicTypeUrl");
    registry.registerKeyManager(privateKeyTypeManager);
    registry.registerKeyManager(publicKeyTypeManager);
    registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager);
    registry.registerKeyManager(privateKeyTypeManager);
    registry.registerKeyManager(publicKeyTypeManager);

    // If one ever registers the two together, we keep that one, so one can get public keys:
    Ed25519PublicKey publicKey =
        Ed25519PublicKey.newBuilder()
            .setVersion(1)
            .setKeyValue(ByteString.copyFrom(new byte[] {0, 1, 2, 3}))
            .build();
    Ed25519PrivateKey privateKey =
        Ed25519PrivateKey.newBuilder().setPublicKey(publicKey).setVersion(1).build();
    KeyData publicKeyData =
        ((PrivateKeyManager) registry.getUntypedKeyManager("privateTypeUrl"))
            .getPublicKeyData(privateKey.toByteString());
    Ed25519PublicKey parsedPublicKey =
        Ed25519PublicKey.parseFrom(
            publicKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(parsedPublicKey).isEqualTo(publicKey);
  }

  @Test
  public void testFips_registerNonFipsKeyTypeManagerFails() throws Exception {
    assumeTrue(TinkFipsUtil.fipsModuleAvailable());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    Registry.restrictToFipsIfEmpty();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.registerKeyManager(
                new TestKeyTypeManager("typeUrl") {
                  @Override
                  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
                    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
                  }
                }));
  }

  @Test
  public void testFips_registerFipsKeyTypeManagerSucceeds() throws Exception {
    assumeTrue(TinkFipsUtil.fipsModuleAvailable());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    Registry.restrictToFipsIfEmpty();

    registry.registerKeyManager(new TestKeyTypeManager("typeUrl"));
  }

  @Test
  public void testFips_registerNonFipsKeyTypeManagerAsymmetricFails() throws Exception {
    assumeTrue(TinkFipsUtil.fipsModuleAvailable());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    Registry.restrictToFipsIfEmpty();

    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.registerAsymmetricKeyManagers(
                new TestPrivateKeyTypeManager("privateTypeUrl") {
                  @Override
                  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
                    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
                  }
                },
                new TestPublicKeyTypeManager("publicTypeUrl")));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.registerAsymmetricKeyManagers(
                new TestPrivateKeyTypeManager("privateTypeUrl"),
                new TestPublicKeyTypeManager("publicTypeUrl") {
                  @Override
                  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
                    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
                  }
                }));
  }

  @Test
  public void testFips_registerFipsKeyTypeManagerAsymmetric_works() throws Exception {
    assumeTrue(TinkFipsUtil.fipsModuleAvailable());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    Registry.restrictToFipsIfEmpty();

    registry.registerAsymmetricKeyManagers(
        new TestPrivateKeyTypeManager("privateTypeUrl"),
        new TestPublicKeyTypeManager("publicTypeUrl"));
  }
}
