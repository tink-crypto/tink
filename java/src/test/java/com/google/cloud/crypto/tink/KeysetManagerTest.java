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

import com.google.cloud.crypto.tink.TestUtil.DummyMacKeyManager;
import com.google.cloud.crypto.tink.TestUtil.EchoAead;
import com.google.cloud.crypto.tink.TestUtil.EchoAeadKeyManager;
import com.google.cloud.crypto.tink.TestUtil.FaultyAead;
import com.google.cloud.crypto.tink.TestUtil.FaultyAeadKeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
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
  private final String macTypeUrl = DummyMacKeyManager.class.getSimpleName();
  private final String echoAeadTypeUrl = EchoAeadKeyManager.class.getSimpleName();
  private final String faultyAeadTypeUrl = FaultyAeadKeyManager.class.getSimpleName();

  @Before
  public void setUp() throws GeneralSecurityException {
    Registry.INSTANCE.registerKeyManager(macTypeUrl, new DummyMacKeyManager());
    Registry.INSTANCE.registerKeyManager(echoAeadTypeUrl, new EchoAeadKeyManager());
    Registry.INSTANCE.registerKeyManager(faultyAeadTypeUrl, new FaultyAeadKeyManager());
  }

  @Test
  public void testBasic() throws Exception {
    KeysetManager manager = new KeysetManager.Builder().build();
    try {
      manager.rotate();
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("cannot rotate, needs key format"));
    }

    // Create a keyset that contains a single DummyMacKey.
    KeyFormat format = KeyFormat.newBuilder().setKeyType(macTypeUrl).build();
    manager = new KeysetManager.Builder()
        .setKeyFormat(format)
        .build();
    manager.rotate();

    assertNull(manager.getKeysetHandle().getEncryptedKeyset());
    Keyset keyset = manager.getKeysetHandle().getKeyset();
    assertEquals(1, keyset.getKeyCount());
    assertEquals(keyset.getPrimaryKeyId(), keyset.getKey(0).getKeyId());
    assertTrue(keyset.getKey(0).hasKeyData());
    assertEquals(macTypeUrl, keyset.getKey(0).getKeyData().getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keyset.getKey(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keyset.getKey(0).getOutputPrefixType());

    // Encrypt the keyset with EchoAead.
    EchoAead echoAead = Registry.INSTANCE.getPrimitive(Registry.INSTANCE.newKey(
        KeyFormat.newBuilder().setKeyType(echoAeadTypeUrl).build()));
    KeysetHandle keysetHandle = manager.getKeysetHandle(echoAead);
    assertNotNull(keysetHandle.getEncryptedKeyset());

    KeysetInfo keysetInfo = keysetHandle.getKeysetInfo();
    assertEquals(1, keysetInfo.getKeyInfoCount());
    assertEquals(keysetInfo.getPrimaryKeyId(), keysetInfo.getKeyInfo(0).getKeyId());
    assertEquals(macTypeUrl, keysetInfo.getKeyInfo(0).getTypeUrl());
    assertEquals(KeyStatusType.ENABLED, keysetInfo.getKeyInfo(0).getStatus());
    assertEquals(OutputPrefixType.TINK, keysetInfo.getKeyInfo(0).getOutputPrefixType());
  }

  @Test
  public void testExistingKeyset() throws Exception {
    // Create a keyset that contains a single DummyMacKey.
    KeyFormat format = KeyFormat.newBuilder().setKeyType(macTypeUrl).build();
    KeysetManager manager1 = new KeysetManager.Builder()
        .setKeyFormat(format)
        .build();
    manager1.rotate();
    Keyset keyset1 = manager1.getKeysetHandle().getKeyset();

    KeysetManager manager2 = new KeysetManager.Builder()
        .setKeysetHandle(manager1.getKeysetHandle())
        .build();
    manager2.rotate(format);
    Keyset keyset2 = manager2.getKeysetHandle().getKeyset();

    assertEquals(2, keyset2.getKeyCount());
    // The new key is the primary key.
    assertEquals(keyset2.getPrimaryKeyId(), keyset2.getKey(1).getKeyId());
  }

  /**
   * Tests that when encryption with KMS failed, an exception is thrown.
   */
  @Test
  public void testFaultyKms() throws Exception {
    // Create a keyset that contains a single DummyMacKey.
    KeyFormat format = KeyFormat.newBuilder().setKeyType(macTypeUrl).build();
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyFormat(format)
        .build();
    manager.rotate();

    // Encrypt with faulty Aead.
    FaultyAead faultyAead = Registry.INSTANCE.getPrimitive(Registry.INSTANCE.newKey(
        KeyFormat.newBuilder().setKeyType(faultyAeadTypeUrl).build()));
    try {
      KeysetHandle keysetHandle = manager.getKeysetHandle(faultyAead);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("encryption with KMS failed"));
    }
  }
}
