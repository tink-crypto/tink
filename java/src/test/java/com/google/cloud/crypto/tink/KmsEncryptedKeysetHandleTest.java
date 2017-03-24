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

import com.google.cloud.crypto.tink.TestUtil.DummyMacKeyManager;
import com.google.cloud.crypto.tink.TestUtil.EchoAead;
import com.google.cloud.crypto.tink.TestUtil.EchoAeadKeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KmsEncryptedKeyset;
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
  private final String macTypeUrl = DummyMacKeyManager.class.getSimpleName();
  private final String echoAeadTypeUrl = EchoAeadKeyManager.class.getSimpleName();

  @Before
  public void setUp() throws GeneralSecurityException {
    Registry.INSTANCE.registerKeyManager(macTypeUrl, new DummyMacKeyManager());
    Registry.INSTANCE.registerKeyManager(echoAeadTypeUrl, new EchoAeadKeyManager());
  }

  @Test
  public void testBasic() throws Exception {
    // Create a keyset that contains a single DummyMacKey.
    KeyFormat format = KeyFormat.newBuilder().setTypeUrl(macTypeUrl).build();
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyFormat(format)
        .build();
    manager.rotate();
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    // Encrypt the keyset with EchoAeadKey.
    KeyData echoAeadKey = Registry.INSTANCE.newKeyData(
        KeyFormat.newBuilder().setTypeUrl(echoAeadTypeUrl).build());
    EchoAead echoAead = Registry.INSTANCE.getPrimitive(echoAeadKey);
    KeysetHandle keysetHandle = manager.getKeysetHandle(echoAead);
    assertNotNull(keysetHandle.getEncryptedKeyset());

    KmsEncryptedKeyset encryptedKeyset = KmsEncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(keysetHandle.getEncryptedKeyset()))
        .setKmsKey(echoAeadKey)
        .setKeysetInfo(keysetHandle.getKeysetInfo())
        .build();

    KeysetHandle keysetHandle2 = KmsEncryptedKeysetHandle.parseFrom(encryptedKeyset);
    assertEquals(keyset, keysetHandle2.getKeyset());
  }

  @Test
  public void testInvalidKeyset() throws Exception {
    // Create a keyset that contains a single DummyMacKey.
    KeyFormat format = KeyFormat.newBuilder().setTypeUrl(macTypeUrl).build();
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyFormat(format)
        .build();
    manager.rotate();

    // Encrypt the keyset with EchoAeadKey.
    KeyData echoAeadKey = Registry.INSTANCE.newKeyData(
        KeyFormat.newBuilder().setTypeUrl(echoAeadTypeUrl).build());
    EchoAead echoAead = Registry.INSTANCE.getPrimitive(echoAeadKey);
    KeysetHandle keysetHandle = manager.getKeysetHandle(echoAead);
    assertNotNull(keysetHandle.getEncryptedKeyset());

    KmsEncryptedKeyset encryptedKeyset = KmsEncryptedKeyset.newBuilder()
        .setEncryptedKeyset(ByteString.copyFrom(keysetHandle.getEncryptedKeyset()))
        .setKmsKey(echoAeadKey)
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
