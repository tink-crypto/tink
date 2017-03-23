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

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.cloud.crypto.tink.TestUtil.DummyMacKeyManager;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyFormat;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for NoSecretKeysetHandle.
 */
@RunWith(JUnit4.class)
public class NoSecretKeysetHandleTest {
  /**
   * A dummy key manager that just returns a remote {@code KeyData}.
   */
  private static class RemoteAeadKeyManager implements KeyManager<Aead, Message, Message> {
    public RemoteAeadKeyManager() {}

    @Override
    public Aead getPrimitive(ByteString serialized) throws GeneralSecurityException {
      return null;
    }
    @Override
    public Aead getPrimitive(Message proto) throws GeneralSecurityException {
      return null;
    }
    @Override
    public Message newKey(ByteString serialized) throws GeneralSecurityException {
      return null;
    }
    @Override
    public Message newKey(Message format) throws GeneralSecurityException {
      return null;
    }
    @Override
    public KeyData newKey(KeyFormat format) throws GeneralSecurityException {
      return KeyData.newBuilder()
          .setTypeUrl(this.getClass().getSimpleName())
          .setKeyMaterialType(KeyData.KeyMaterialType.REMOTE)
          .build();
    }
    @Override
    public boolean doesSupport(String typeUrl) {
      return true;
    }
  }

  private static final String MAC_TYPE_URL = DummyMacKeyManager.class.getSimpleName();
  private static final String AEAD_TYPE_URL = RemoteAeadKeyManager.class.getSimpleName();

  @Before
  public void setUp() throws GeneralSecurityException {
    Registry.INSTANCE.registerKeyManager(MAC_TYPE_URL, new DummyMacKeyManager());
    Registry.INSTANCE.registerKeyManager(AEAD_TYPE_URL, new RemoteAeadKeyManager());
  }

  @Test
  public void testBasic() throws Exception {
    KeyFormat format = KeyFormat.newBuilder().setTypeUrl(MAC_TYPE_URL).build();
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyFormat(format)
        .build()
        .rotate();
    assertNull(manager.getKeysetHandle().getEncryptedKeyset());
    Keyset keyset = manager.getKeysetHandle().getKeyset();
    try {
      KeysetHandle unused = NoSecretKeysetHandle.parseFrom(keyset.toByteArray());
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertTrue(e.toString().contains("keyset contains secret key material"));
    }

    KeyFormat format2 = KeyFormat.newBuilder().setTypeUrl(AEAD_TYPE_URL).build();
    KeysetManager manager2 = new KeysetManager.Builder()
        .setKeyFormat(format2)
        .build()
        .rotate();
    Keyset keyset2 = manager2.getKeysetHandle().getKeyset();
    try {
      KeysetHandle unused = NoSecretKeysetHandle.parseFrom(keyset2.toByteArray());
    } catch (GeneralSecurityException e) {
      fail("Should be allowed to load non secret keyset");
    }
  }
}
