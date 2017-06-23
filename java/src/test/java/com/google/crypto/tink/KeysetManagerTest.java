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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.hybrid.HybridDecryptConfig;
import com.google.crypto.tink.hybrid.HybridEncryptConfig;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import com.google.crypto.tink.proto.OutputPrefixType;
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
      HmacKeyManager.TYPE_URL;

  @Before
  public void setUp() throws GeneralSecurityException {
    AeadConfig.registerStandardKeyTypes();
    MacConfig.registerStandardKeyTypes();
    HybridEncryptConfig.registerStandardKeyTypes();
    HybridDecryptConfig.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    KeysetManager manager = new KeysetManager.Builder().build();
    try {
      manager.rotate();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "cannot rotate, needs key template");
    }

    // Create a keyset that contains a single HmacKey.
    manager = new KeysetManager.Builder()
        .setKeyTemplate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
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
  }

  @Test
  public void testEncryptedKeyset() throws Exception {
    // Create an encrypted keyset that contains a single HmacKey.
    KeyTemplate masterKeyTemplate = AeadKeyTemplates.AES128_GCM;
    KeyData aeadKeyData = Registry.INSTANCE.newKeyData(masterKeyTemplate);
    Aead masterKey = Registry.INSTANCE.getPrimitive(aeadKeyData);
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
        .setMasterKey(masterKey)
        .build()
        .rotate();
    KeysetHandle keysetHandle = manager.getKeysetHandle();
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
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
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
    // Encrypt with dummy Aead.
    TestUtil.DummyAead masterKey = new TestUtil.DummyAead();
    try {
      KeysetHandle unused = new KeysetManager.Builder()
          .setKeyTemplate(MacKeyTemplates.HMAC_SHA256_128BITTAG)
          .setMasterKey(masterKey)
          .build()
          .rotate()
          .getKeysetHandle();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "dummy");
    }
  }
}
