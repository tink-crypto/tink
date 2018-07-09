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
import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil.DummyAead;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.crypto.tink.subtle.MacJce;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.BeforeClass;
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
    public KeyData newKeyData(ByteString serialized) throws GeneralSecurityException {
      throw new GeneralSecurityException("Not Implemented");
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
  }

  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    Config.register(TinkConfig.TINK_1_0_0);
  }

  private void testGetKeyManager_shouldWork(String typeUrl, String className) throws Exception {
    assertThat(Registry.getKeyManager(typeUrl).getClass().toString()).contains(className);
  }

  @Test
  public void testGetKeyManager_shouldWork() throws Exception {
    testGetKeyManager_shouldWork(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL, "AesCtrHmacAeadKeyManager");
    testGetKeyManager_shouldWork(AeadConfig.AES_EAX_TYPE_URL, "AesEaxKeyManager");
    testGetKeyManager_shouldWork(MacConfig.HMAC_TYPE_URL, "HmacKeyManager");
  }

  @Test
  public void testGetKeyManager_wrongType_shouldThrowException() throws Exception {
    // TODO(thaidn): make this assignment throw some exception.
    KeyManager<Aead> wrongType = Registry.getKeyManager(MacConfig.HMAC_TYPE_URL);
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    HmacKey hmacKey = (HmacKey) Registry.newKey(template);

    try {
      Aead unused = wrongType.getPrimitive(hmacKey);
      fail("Expected ClassCastException");
    } catch (ClassCastException e) {
      assertExceptionContains(e, "MacJce cannot be cast to com.google.crypto.tink.Aead");
    }
  }

  @Test
  public void testGetKeyManager_badTypeUrl_shouldThrowException() throws Exception {
    String badTypeUrl = "bad type URL";

    try {
      Registry.getKeyManager(badTypeUrl);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "No key manager found");
      assertExceptionContains(e, badTypeUrl);
    }
  }

  @Test
  public void testRegisterKeyManager_keyManagerIsNull_shouldThrowException() throws Exception {
    try {
      Registry.registerKeyManager(null);
      fail("Expected IllegalArgumentException.");
    } catch (IllegalArgumentException e) {
      assertThat(e.toString()).contains("must be non-null");
    }
  }

  @Test
  public void testRegisterKeyManager_MoreRestrictedNewKeyAllowed_shouldWork() throws Exception {
    String typeUrl = "someTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl));

    try {
      Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), false);
    } catch (GeneralSecurityException e) {
      throw new AssertionError(
          "repeated registrations of the same key manager should work", e);
    }
  }

  @Test
  public void testRegisterKeyManager_SameNewKeyAllowed_shouldWork() throws Exception {
    String typeUrl = "someOtherTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl));

    try {
      Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), true);
    } catch (GeneralSecurityException e) {
      throw new AssertionError(
          "repeated registrations of the same key manager should work", e);
    }
  }

  @Test
  public void testRegisterKeyManager_LessRestrictedNewKeyAllowed_shouldThrowException()
      throws Exception {
    String typeUrl = "yetAnotherTypeUrl";
    Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), false);

    try {
      Registry.registerKeyManager(new CustomAeadKeyManager(typeUrl), true);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void testRegisterKeyManager_keyManagerFromAnotherClass_shouldThrowException()
      throws Exception {
    // This should not overwrite the existing manager.
    try {
      Registry.registerKeyManager(new CustomAeadKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL));
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("already registered");
    }

    KeyManager<Aead> manager = Registry.getKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL);
    assertThat(manager.getClass().toString()).contains("AesCtrHmacAeadKeyManager");
  }

  @Test
  public void testRegisterKeyManager_deprecated_keyManagerIsNull_shouldThrowException()
      throws Exception {
    try {
      Registry.registerKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL, null);
      fail("Expected IllegalArgumentException.");
    } catch (IllegalArgumentException e) {
      assertThat(e.toString()).contains("must be non-null");
    }
  }

  @Test
  public void testRegisterKeyManager_deprecated_WithKeyTypeNotSupported_shouldThrowException()
      throws Exception {
    String typeUrl = "yetSomeOtherTypeUrl";
    String differentTypeUrl = "differentTypeUrl";
    try {
      Registry.registerKeyManager(differentTypeUrl, new CustomAeadKeyManager(typeUrl));
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e,
          "Manager does not support key type " + differentTypeUrl);
      return;
    }
    fail("Should throw an exception.");
  }

  @Test
  public void testRegisterKeyManager_deprecated_MoreRestrictedNewKeyAllowed_shouldWork()
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
  public void testRegisterKeyManager_deprecated_LessRestrictedNewKeyAllowed_shouldThrowException()
      throws Exception {
    String typeUrl = "totallyDifferentTypeUrl";
    Registry.registerKeyManager(typeUrl, new CustomAeadKeyManager(typeUrl), false);

    try {
      Registry.registerKeyManager(typeUrl, new CustomAeadKeyManager(typeUrl), true);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void testRegisterKeyManager_deprecated_keyManagerFromAnotherClass_shouldThrowException()
      throws Exception {
    // This should not overwrite the existing manager.
    try {
      Registry.registerKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL,
          new CustomAeadKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL));
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertThat(e.toString()).contains("already registered");
    }

    KeyManager<Aead> manager = Registry.getKeyManager(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL);
    assertThat(manager.getClass().toString()).contains("AesCtrHmacAeadKeyManager");
  }

  @Test
  public void testGetPrimitive_AesGcm_shouldWork() throws Exception {
    KeyTemplate template = AeadKeyTemplates.AES128_EAX;
    AesEaxKey aesEaxKey = (AesEaxKey) Registry.newKey(template);
    KeyData aesEaxKeyData = Registry.newKeyData(template);
    Aead aead = Registry.getPrimitive(aesEaxKeyData);

    assertThat(aesEaxKey.getKeyValue().size()).isEqualTo(16);
    assertThat(aesEaxKeyData.getTypeUrl()).isEqualTo(AeadConfig.AES_EAX_TYPE_URL);
    // This might break when we add native implementations.
    assertThat(aead.getClass()).isEqualTo(AesEaxJce.class);
  }

  @Test
  public void testGetPrimitive_Hmac_shouldWork() throws Exception {
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    HmacKey hmacKey = (HmacKey) Registry.newKey(template);
    KeyData hmacKeyData = Registry.newKeyData(template);
    Mac mac = Registry.getPrimitive(hmacKeyData);

    assertThat(hmacKey.getKeyValue().size()).isEqualTo(32);
    assertThat(hmacKey.getParams().getTagSize()).isEqualTo(16);
    assertThat(hmacKey.getParams().getHash()).isEqualTo(HashType.SHA256);
    assertThat(hmacKeyData.getTypeUrl()).isEqualTo(MacConfig.HMAC_TYPE_URL);
    // This might break when we add native implementations.
    assertThat(mac.getClass()).isEqualTo(MacJce.class);
  }

  @Test
  public void testGetPrimitives_shouldWork() throws Exception {
    // Create a keyset, and get a PrimitiveSet.
    KeyTemplate template1 = AeadKeyTemplates.AES128_EAX;
    KeyTemplate template2 = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    KeyData key1 = Registry.newKeyData(template1);
    KeyData key2 = Registry.newKeyData(template1);
    KeyData key3 = Registry.newKeyData(template2);
    KeysetHandle keysetHandle =
        KeysetHandle.fromKeyset(
            Keyset.newBuilder()
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key1)
                        .setKeyId(1)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key2)
                        .setKeyId(2)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key3)
                        .setKeyId(3)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .setPrimaryKeyId(2)
                .build());
    PrimitiveSet<Aead> aeadSet = Registry.getPrimitives(keysetHandle);

    assertThat(aeadSet.getPrimary().getPrimitive().getClass()).isEqualTo(AesEaxJce.class);
  }

  @Test
  public void testGetPrimitives_WithSomeNonEnabledKeys_shouldWork() throws Exception {
    // Try a keyset with some keys non-ENABLED.
    KeyTemplate template1 = AeadKeyTemplates.AES128_EAX;
    KeyTemplate template2 = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    KeyData key1 = Registry.newKeyData(template1);
    KeyData key2 = Registry.newKeyData(template1);
    KeyData key3 = Registry.newKeyData(template2);
    KeysetHandle keysetHandle =
        KeysetHandle.fromKeyset(
            Keyset.newBuilder()
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key1)
                        .setKeyId(1)
                        .setStatus(KeyStatusType.DESTROYED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key2)
                        .setKeyId(2)
                        .setStatus(KeyStatusType.DISABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key3)
                        .setKeyId(3)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .setPrimaryKeyId(3)
                .build());
    PrimitiveSet<Aead> aeadSet = Registry.getPrimitives(keysetHandle);

    assertThat(aeadSet.getPrimary().getPrimitive().getClass())
        .isEqualTo(EncryptThenAuthenticate.class);
  }

  @Test
  public void testGetPrimitives_CustomManager_shouldWork() throws Exception {
    // Create a keyset.
    KeyTemplate template1 = AeadKeyTemplates.AES128_EAX;
    KeyTemplate template2 = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    KeyData key1 = Registry.newKeyData(template1);
    KeyData key2 = Registry.newKeyData(template2);
    KeysetHandle keysetHandle =
        KeysetHandle.fromKeyset(
            Keyset.newBuilder()
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key1)
                        .setKeyId(1)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key2)
                        .setKeyId(2)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .setPrimaryKeyId(2)
                .build());

    // Get a PrimitiveSet using a custom key manager for key1.
    KeyManager<Aead> customManager = new CustomAeadKeyManager(AeadConfig.AES_EAX_TYPE_URL);
    PrimitiveSet<Aead> aeadSet = Registry.getPrimitives(keysetHandle, customManager);
    List<PrimitiveSet.Entry<Aead>> aead1List =
        aeadSet.getPrimitive(keysetHandle.getKeyset().getKey(0));
    List<PrimitiveSet.Entry<Aead>> aead2List =
        aeadSet.getPrimitive(keysetHandle.getKeyset().getKey(1));

    assertThat(aead1List.size()).isEqualTo(1);
    assertThat(aead1List.get(0).getPrimitive().getClass()).isEqualTo(DummyAead.class);
    assertThat(aead2List.size()).isEqualTo(1);
    assertThat(aead2List.get(0).getPrimitive().getClass()).isEqualTo(EncryptThenAuthenticate.class);
  }

  @Test
  public void testGetPrimitives_EmptyKeyset_shouldThrowException() throws Exception {
    // Empty keyset.
    try {
      Registry.getPrimitives(KeysetHandle.fromKeyset(Keyset.newBuilder().build()));
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }
  }

  @Test
  public void testGetPrimitives_KeysetWithNoPrimaryKey_shouldThrowException() throws Exception {
    // Create a keyset without a primary key.
    KeyData key1 = Registry.newKeyData(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    KeysetHandle keysetHandle =
        KeysetHandle.fromKeyset(
            Keyset.newBuilder()
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key1)
                        .setKeyId(1)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .build());

    // No primary key.
    try {
      Registry.getPrimitives(keysetHandle);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset doesn't contain a valid primary key");
    }
  }

  @Test
  public void testGetPrimitives_KeysetWithDisabledPrimaryKey_shouldThrowException()
      throws Exception {
    // Create a keyset with a disabled primary key.
    KeyData key1 = Registry.newKeyData(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    KeysetHandle keysetHandle =
        KeysetHandle.fromKeyset(
            Keyset.newBuilder()
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key1)
                        .setKeyId(1)
                        .setStatus(KeyStatusType.DISABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .setPrimaryKeyId(1)
                .build());

    try {
      Registry.getPrimitives(keysetHandle);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset doesn't contain a valid primary key");
    }
  }

  @Test
  public void testGetPrimitives_KeysetWithMultiplePrimaryKeys_shouldThrowException()
      throws Exception {
    // Multiple primary keys.
    KeyData key1 = Registry.newKeyData(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    KeysetHandle keysetHandle =
        KeysetHandle.fromKeyset(
            Keyset.newBuilder()
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key1)
                        .setKeyId(1)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .addKey(
                    Keyset.Key.newBuilder()
                        .setKeyData(key1)
                        .setKeyId(1)
                        .setStatus(KeyStatusType.ENABLED)
                        .setOutputPrefixType(OutputPrefixType.TINK)
                        .build())
                .setPrimaryKeyId(1)
                .build());

    try {
      Registry.getPrimitives(keysetHandle);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "keyset contains multiple primary keys");
    }
  }

  private static class Catalogue1 implements Catalogue {
    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    public KeyManager getKeyManager(String typeUrl, String primitiveName, int minVersion) {
      return null;
    }
  }

  private static class Catalogue2 implements Catalogue {
    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    public KeyManager getKeyManager(String typeUrl, String primitiveName, int minVersion) {
      return null;
    }
  }

  private static class Catalogue3 implements Catalogue {
    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    public KeyManager getKeyManager(String typeUrl, String primitiveName, int minVersion) {
      return null;
    }
  }

  @Test
  public void testAddCatalogue_MultiThreads_shouldWork() throws Exception {
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
}
