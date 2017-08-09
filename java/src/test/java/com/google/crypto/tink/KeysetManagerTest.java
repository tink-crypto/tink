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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.hybrid.HybridDecryptConfig;
import com.google.crypto.tink.hybrid.HybridEncryptConfig;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
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
    // Create a keyset that contains a single HmacKey.
    KeysetManager manager = KeysetManager.withEmptyKeyset()
        .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    Keyset keyset = manager.getKeysetHandle().getKeyset();
    assertEquals(1, keyset.getKeyCount());
    assertEquals(keyset.getPrimaryKeyId(), keyset.getKey(0).getKeyId());
    assertTrue(keyset.getKey(0).hasKeyData());
    assertEquals(hmacKeyTypeUrl, keyset.getKey(0).getKeyData().getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keyset.getKey(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keyset.getKey(0).getOutputPrefixType());
  }

  @Test
  public void testExistingKeyset() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeysetManager manager1 = KeysetManager.withEmptyKeyset()
        .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    Keyset keyset1 = manager1.getKeysetHandle().getKeyset();

    KeysetManager manager2 = KeysetManager
        .fromKeysetHandle(manager1.getKeysetHandle())
        .rotate(MacKeyTemplates.HMAC_SHA256_128BITTAG);
    Keyset keyset2 = manager2.getKeysetHandle().getKeyset();

    assertEquals(2, keyset2.getKeyCount());
    // The first key in two keysets should be the same.
    assertEquals(keyset1.getKey(0), keyset2.getKey(0));
    // The new key is the primary key.
    assertEquals(keyset2.getPrimaryKeyId(), keyset2.getKey(1).getKeyId());
  }
}
