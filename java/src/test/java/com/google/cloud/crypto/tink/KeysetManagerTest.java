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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.TestUtil.DummyAead;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.mac.MacFactory;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for KeysetManager.
 */
@RunWith(JUnit4.class)
public class KeysetManagerTest {
  private String hmacKeyTypeUrl =
      "type.googleapis.com/google.cloud.crypto.tink.HmacKey";

  @Before
  public void setUp() throws GeneralSecurityException {
    AeadFactory.registerStandardKeyTypes();
    MacFactory.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    KeysetManager manager = new KeysetManager.Builder().build();
    try {
      manager.rotate();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("cannot rotate, needs key template"));
    }

    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = TestUtil.createHmacKeyTemplate(
        16 /* key size */, 16 /* tag size */, HashType.SHA256);
    manager = new KeysetManager.Builder()
        .setKeyTemplate(template)
        .build()
        .rotate();

    assertNull(manager.getKeysetHandle().getEncryptedKeyset());
    Keyset keyset = manager.getKeysetHandle().getKeyset();
    assertEquals(1, keyset.getKeyCount());
    assertEquals(keyset.getPrimaryKeyId(), keyset.getKey(0).getKeyId());
    assertTrue(keyset.getKey(0).hasKeyData());
    assertEquals(hmacKeyTypeUrl, keyset.getKey(0).getKeyData().getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keyset.getKey(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keyset.getKey(0).getOutputPrefixType());

    // Encrypt the keyset with an AeadKey.
    template = TestUtil.createAesGcmKeyTemplate(16 /* key size */);
    KeyData aeadKeyData = Registry.INSTANCE.newKeyData(template);
    Aead aead = Registry.INSTANCE.getPrimitive(aeadKeyData);
    KeysetHandle keysetHandle = manager.getKeysetHandle(aead);
    assertNotNull(keysetHandle.getEncryptedKeyset());

    KeysetInfo keysetInfo = keysetHandle.getKeysetInfo();
    assertEquals(1, keysetInfo.getKeyInfoCount());
    assertEquals(keysetInfo.getPrimaryKeyId(), keysetInfo.getKeyInfo(0).getKeyId());
    assertEquals(hmacKeyTypeUrl, keysetInfo.getKeyInfo(0).getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keysetInfo.getKeyInfo(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keysetInfo.getKeyInfo(0).getOutputPrefixType());
  }

  @Test
  public void testExistingKeyset() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = TestUtil.createHmacKeyTemplate(
        16 /* key size */, 16 /* tag size */, HashType.SHA256);
    KeysetManager manager1 = new KeysetManager.Builder()
        .setKeyTemplate(template)
        .build()
        .rotate();
    Keyset keyset1 = manager1.getKeysetHandle().getKeyset();

    KeysetManager manager2 = new KeysetManager.Builder()
        .setKeysetHandle(manager1.getKeysetHandle())
        .build()
        .rotate(template);
    Keyset keyset2 = manager2.getKeysetHandle().getKeyset();

    assertEquals(2, keyset2.getKeyCount());
    // The first key in two keysets should be the same.
    assertEquals(keyset1.getKey(0), keyset2.getKey(0));
    // The new key is the primary key.
    assertEquals(keyset2.getPrimaryKeyId(), keyset2.getKey(1).getKeyId());
  }

  /**
   * Tests that when encryption with KMS failed, an exception is thrown.
   */
  @Test
  public void testFaultyKms() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = TestUtil.createHmacKeyTemplate(
        16 /* key size */, 16 /* tag size */, HashType.SHA256);
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(template)
        .build()
        .rotate();

    // Encrypt with dummy Aead.
    DummyAead aead = new DummyAead();
    try {
      KeysetHandle unused = manager.getKeysetHandle(aead);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("dummy"));
    }
  }
}
