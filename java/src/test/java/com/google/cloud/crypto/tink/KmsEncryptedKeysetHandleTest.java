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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KmsEncryptedKeyset;
import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for KmsEncryptedKeysetHandle.
 */
@RunWith(JUnit4.class)
public class KmsEncryptedKeysetHandleTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    AeadFactory.registerStandardKeyTypes();
    MacFactory.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = TestUtil.createHmacKeyTemplate(
        16 /* key size */, 16 /* tag size */, HashType.SHA256);
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(template)
        .build()
        .rotate();
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    // Encrypt the keyset with an AeadKey.
    template = TestUtil.createAesGcmKeyTemplate(16 /* key size */);
    KeyData aeadKeyData = Registry.INSTANCE.newKeyData(template);
    Aead aead = Registry.INSTANCE.getPrimitive(aeadKeyData);
    KeysetHandle keysetHandle = manager.getKeysetHandle(aead);
    assertNotNull(keysetHandle.getEncryptedKeyset());

    KmsEncryptedKeyset encryptedKeyset = KmsEncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(keysetHandle.getEncryptedKeyset()))
        .setKmsKey(aeadKeyData)
        .setKeysetInfo(keysetHandle.getKeysetInfo())
        .build();

    KeysetHandle keysetHandle2 = KmsEncryptedKeysetHandle.parseFrom(encryptedKeyset);
    assertEquals(keyset, keysetHandle2.getKeyset());
  }

  @Test
  public void testInvalidKeyset() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = TestUtil.createHmacKeyTemplate(
        16 /* key size */, 16 /* tag size */, HashType.SHA256);
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(template)
        .build()
        .rotate();

    // Encrypt the keyset with an AeadKey.
    template = TestUtil.createAesGcmKeyTemplate(16 /* key size */);
    KeyData aeadKeyData = Registry.INSTANCE.newKeyData(template);
    Aead aead = Registry.INSTANCE.getPrimitive(aeadKeyData);
    KeysetHandle keysetHandle = manager.getKeysetHandle(aead);
    assertNotNull(keysetHandle.getEncryptedKeyset());

    KmsEncryptedKeyset encryptedKeyset = KmsEncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(keysetHandle.getEncryptedKeyset()))
        .setKmsKey(aeadKeyData)
        .setKeysetInfo(keysetHandle.getKeysetInfo())
        .build();

    byte[] proto = encryptedKeyset.toByteArray();
    proto[0] = (byte) ~proto[0];
    try {
      KeysetHandle unused = KmsEncryptedKeysetHandle.parseFrom(proto);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("invalid keyset"));
    }

    KmsEncryptedKeyset encryptedKeySet2 = encryptedKeyset.toBuilder()
        .clearEncryptedKeyset()
        .build();
    try {
      KeysetHandle unused = KmsEncryptedKeysetHandle.parseFrom(encryptedKeySet2);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("invalid keyset"));
    }

    KmsEncryptedKeyset encryptedKeySet3 = encryptedKeyset.toBuilder()
        .clearKmsKey()
        .build();
    try {
      KeysetHandle unused = KmsEncryptedKeysetHandle.parseFrom(encryptedKeySet3);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("invalid keyset"));
    }
  }
}
