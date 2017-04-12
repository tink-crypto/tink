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

package com.google.cloud.crypto.tink;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKey;
import com.google.cloud.crypto.tink.AesCtrHmacAeadProto.AesCtrHmacAeadKeyFormat;
import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKey;
import com.google.cloud.crypto.tink.AesGcmProto.AesGcmKeyFormat;
import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.HmacProto.HmacKey;
import com.google.cloud.crypto.tink.HmacProto.HmacKeyFormat;
import com.google.cloud.crypto.tink.TestUtil.DummyAead;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.cloud.crypto.tink.subtle.AesGcmJce;
import com.google.cloud.crypto.tink.subtle.EncryptThenAuthenticate;
import com.google.cloud.crypto.tink.subtle.MacJce;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for Registry.
 */
@RunWith(JUnit4.class)
public class RegistryTest {
  private static class CustomAeadKeyManager implements KeyManager<Aead, MessageLite, MessageLite> {
    public CustomAeadKeyManager() {}
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
    public boolean doesSupport(String typeUrl) {  // supports same keys as AesGcmKey
      return typeUrl.equals("type.googleapis.com/google.cloud.crypto.tink.AesGcmKey");
    }
  }

  private String aesCtrHmacAeadTypeUrl =
      "type.googleapis.com/google.cloud.crypto.tink.AesCtrHmacAeadKey";
  private String aesGcmTypeUrl =
      "type.googleapis.com/google.cloud.crypto.tink.AesGcmKey";
  private String hmacKeyTypeUrl =
      "type.googleapis.com/google.cloud.crypto.tink.HmacKey";

  @Before
  public void setUp() throws GeneralSecurityException {
    AeadFactory.registerStandardKeyTypes();
    MacFactory.registerStandardKeyTypes();
  }

  @Test
  public void testKeyManagerRegistration() throws Exception {
    // Retrieve some key managers.
    KeyManager<Aead, AesCtrHmacAeadKey, AesCtrHmacAeadKeyFormat> aesCtrHmacAeadManager =
        Registry.INSTANCE.getKeyManager(aesCtrHmacAeadTypeUrl);
    assertTrue(aesCtrHmacAeadManager.getClass().toString().contains(
        "AesCtrHmacAeadKeyManager"));

    KeyManager<Aead, AesGcmKey, AesGcmKeyFormat> aesGcmManager =
        Registry.INSTANCE.getKeyManager(aesGcmTypeUrl);
    assertTrue(aesGcmManager.getClass().toString().contains(
        "AesGcmKeyManager"));

    KeyManager<Mac, HmacKey, HmacKeyFormat> hmacManager =
        Registry.INSTANCE.getKeyManager(hmacKeyTypeUrl);
    assertTrue(hmacManager.getClass().toString().contains(
        "HmacKeyManager"));

    // TODO(thaidn): make this assignment throw some exception.
    KeyManager<Aead, HmacKey, HmacKeyFormat> wrongType =
        Registry.INSTANCE.getKeyManager(hmacKeyTypeUrl);
    assertTrue(wrongType.getClass().toString().contains(
        "HmacKeyManager"));
    KeyTemplate template = TestUtil.createHmacKeyTemplate(
        16 /* key size */, 16 /* tag size */, HashType.SHA256);
    HmacKey hmacKey = Registry.INSTANCE.newKey(template);
    try {
      Aead unused = wrongType.getPrimitive(hmacKey);
      fail("Expected ClassCastException");
    } catch (ClassCastException e) {
      assertTrue(e.toString().contains(
          "MacJce cannot be cast to com.google.cloud.crypto.tink.Aead"));
    }

    String badTypeUrl = "bad type URL";
    try {
      KeyManager<Mac, MessageLite, MessageLite> unused =
          Registry.INSTANCE.getKeyManager(badTypeUrl);
      fail("Expected GeneralSecurityException.");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("unsupported"));
      assertTrue(e.toString().contains(badTypeUrl));
    }
  }

  @Test
  public void testKeyAndPrimitiveCreation() throws Exception {
    // Create some keys and primitives.
    KeyTemplate template =  TestUtil.createAesGcmKeyTemplate(16 /* key_size */);
    AesGcmKey aesGcmKey = Registry.INSTANCE.newKey(template);
    assertEquals(16, aesGcmKey.getKeyValue().size());
    KeyData aesGcmKeyData = Registry.INSTANCE.newKeyData(template);
    assertEquals(aesGcmTypeUrl, aesGcmKeyData.getTypeUrl());
    Aead aead = Registry.INSTANCE.getPrimitive(aesGcmKeyData);
    // This might break when we add native implementations.
    assertEquals(AesGcmJce.class, aead.getClass());

    template = TestUtil.createHmacKeyTemplate(
        16 /* key size */, 10 /* tag size */, HashType.SHA256);
    HmacKey hmacKey = Registry.INSTANCE.newKey(template);
    assertEquals(16, hmacKey.getKeyValue().size());
    assertEquals(10, hmacKey.getParams().getTagSize());
    assertEquals(HashType.SHA256, hmacKey.getParams().getHash());
    KeyData hmacKeyData = Registry.INSTANCE.newKeyData(template);
    assertEquals(hmacKeyTypeUrl, hmacKeyData.getTypeUrl());
    Mac mac = Registry.INSTANCE.getPrimitive(hmacKeyData);
    // This might break when we add native implementations.
    assertEquals(MacJce.class, mac.getClass());

    // Create a keyset, and get a PrimitiveSet.
    KeyTemplate template1 =  TestUtil.createAesGcmKeyTemplate(16 /* key_size */);
    KeyTemplate template2 =  TestUtil.createAesCtrHmacAeadKeyTemplate(
        16 /* AES key size */,
        12 /* IV size */,
        16 /* HMAC key size */,
        10 /* tag size */);
    KeyData key1 = Registry.INSTANCE.newKeyData(template1);
    KeyData key2 = Registry.INSTANCE.newKeyData(template1);
    KeyData key3 = Registry.INSTANCE.newKeyData(template2);
    KeysetHandle keysetHandle = new KeysetHandle(Keyset.newBuilder()
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key1)
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key2)
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key3)
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .setPrimaryKeyId(2)
        .build());
    PrimitiveSet<Aead> aeadSet = Registry.INSTANCE.getPrimitives(keysetHandle);
    assertEquals(AesGcmJce.class, aeadSet.getPrimary().getPrimitive().getClass());

    // Try a keyset with some keys non-ENABLED.
    keysetHandle = new KeysetHandle(Keyset.newBuilder()
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key1)
            .setKeyId(1)
            .setStatus(KeyStatusType.DESTROYED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key2)
            .setKeyId(2)
            .setStatus(KeyStatusType.DISABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key3)
            .setKeyId(3)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .setPrimaryKeyId(3)
        .build());
    aeadSet = Registry.INSTANCE.getPrimitives(keysetHandle);
    assertEquals(EncryptThenAuthenticate.class,
        aeadSet.getPrimary().getPrimitive().getClass());
  }


  @Test
  public void testRegistryCollisions() throws Exception {
    try {
      Registry.INSTANCE.registerKeyManager(aesCtrHmacAeadTypeUrl, null);
      fail("Expected NullPointerException.");
    } catch (NullPointerException e) {
      assertTrue(e.toString().contains("must be non-null"));
    }
    // This should not overwrite the existing manager.
    assertFalse(Registry.INSTANCE.registerKeyManager(aesCtrHmacAeadTypeUrl,
        new CustomAeadKeyManager()));
    KeyManager<Aead, MessageLite, MessageLite> manager =
       Registry.INSTANCE.getKeyManager(aesCtrHmacAeadTypeUrl);
    assertNotEquals(CustomAeadKeyManager.class, manager.getClass());
    assertTrue(manager.getClass().toString().contains(
        "AesCtrHmacAeadKeyManager"));
  }

  @Test
  public void testInvalidKeyset() throws Exception {
    // Empty keyset.
    try {
      Registry.INSTANCE.getPrimitives(new KeysetHandle(Keyset.newBuilder().build()));
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("empty keyset"));
    }

    // Create a keyset.
    KeyTemplate template1 =  TestUtil.createHmacKeyTemplate(
        16 /* key size */, 10 /* tag size */, HashType.SHA256);
    KeyData key1 = Registry.INSTANCE.newKeyData(template1);
    // No primary key.
    KeysetHandle keysetHandle = new KeysetHandle(Keyset.newBuilder()
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key1)
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .build());
    // No primary key.
    try {
      Registry.INSTANCE.getPrimitives(keysetHandle);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("keyset doesn't contain a valid primary key"));
    }

    // Primary key is disabled.
    keysetHandle = new KeysetHandle(Keyset.newBuilder()
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key1)
            .setKeyId(1)
            .setStatus(KeyStatusType.DISABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .setPrimaryKeyId(1)
        .build());
    try {
      Registry.INSTANCE.getPrimitives(keysetHandle);
      fail("Invalid keyset. Expect GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("keyset doesn't contain a valid primary key"));
    }
  }

  @Test
  public void testCustomKeyManagerHandling() throws Exception {
    // Create a keyset.
    KeyTemplate template1 =  TestUtil.createAesGcmKeyTemplate(16 /* key_size */);
    KeyTemplate template2 =  TestUtil.createAesCtrHmacAeadKeyTemplate(
        16 /* AES key size */,
        12 /* IV size */,
        16 /* HMAC key size */,
        10 /* tag size */);
    KeyData key1 = Registry.INSTANCE.newKeyData(template1);
    KeyData key2 = Registry.INSTANCE.newKeyData(template2);
    KeysetHandle keysetHandle = new KeysetHandle(Keyset.newBuilder()
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key1)
            .setKeyId(1)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .addKey(Keyset.Key.newBuilder()
            .setKeyData(key2)
            .setKeyId(2)
            .setStatus(KeyStatusType.ENABLED)
            .setOutputPrefixType(OutputPrefixType.TINK)
            .build())
        .setPrimaryKeyId(2)
        .build());
    // Get a PrimitiveSet using registered key managers.
    PrimitiveSet<Aead> aeadSet = Registry.INSTANCE.getPrimitives(keysetHandle);
    List<PrimitiveSet<Aead>.Entry<Aead>> aead1List =
        aeadSet.getPrimitive(keysetHandle.getKeyset().getKey(0));
    List<PrimitiveSet<Aead>.Entry<Aead>> aead2List =
        aeadSet.getPrimitive(keysetHandle.getKeyset().getKey(1));
    assertEquals(1, aead1List.size());
    assertEquals(AesGcmJce.class, aead1List.get(0).getPrimitive().getClass());
    assertEquals(1, aead2List.size());
    assertEquals(EncryptThenAuthenticate.class, aead2List.get(0).getPrimitive().getClass());

    // Get a PrimitiveSet using a custom key manager for key1.
    KeyManager<Aead, MessageLite, MessageLite> customManager = new CustomAeadKeyManager();
    aeadSet = Registry.INSTANCE.getPrimitives(keysetHandle, customManager);
    aead1List = aeadSet.getPrimitive(keysetHandle.getKeyset().getKey(0));
    aead2List = aeadSet.getPrimitive(keysetHandle.getKeyset().getKey(1));
    assertEquals(1, aead1List.size());
    assertEquals(DummyAead.class, aead1List.get(0).getPrimitive().getClass());
    assertEquals(1, aead2List.size());
    assertEquals(EncryptThenAuthenticate.class, aead2List.get(0).getPrimitive().getClass());
  }

  // TODO(przydatek): Add more tests for creation of PrimitiveSets.
}
