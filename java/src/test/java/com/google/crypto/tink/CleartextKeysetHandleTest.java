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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacFactory;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for CleartextKeysetHandle.
 */
@RunWith(JUnit4.class)
public class CleartextKeysetHandleTest {
  @Before
  public void setUp() throws GeneralSecurityException {
    MacConfig.registerStandardKeyTypes();
  }

  @Test
  public void testBasic() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(template)
        .build()
        .rotate();

    assertNull(manager.getKeysetHandle().getEncryptedKeyset());
    Keyset keyset1 = manager.getKeysetHandle().getKeyset();

    // Parse directly from a byte array
    KeysetHandle handle1 = CleartextKeysetHandle.parseFrom(keyset1.toByteArray());
    assertEquals(keyset1, handle1.getKeyset());

    // Parse from an inputStream
    handle1 = CleartextKeysetHandle.parseFrom(new ByteArrayInputStream(keyset1.toByteArray()));
    assertEquals(keyset1, handle1.getKeyset());

    KeysetHandle handle2 = CleartextKeysetHandle.generateNew(template);
    Keyset keyset2 = handle2.getKeyset();
    assertEquals(1, keyset2.getKeyCount());
    Keyset.Key key2 = keyset2.getKey(0);
    assertEquals(keyset2.getPrimaryKeyId(), key2.getKeyId());
    assertEquals(template.getTypeUrl(), key2.getKeyData().getTypeUrl());
    Mac unused = MacFactory.getPrimitive(handle2);  // instantiation should succeed
  }

  @Test
  public void testInvalidKeyset() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetManager manager = new KeysetManager.Builder()
        .setKeyTemplate(template)
        .build()
        .rotate();
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    byte[] proto = keyset.toByteArray();
    proto[0] = (byte) ~proto[0];
    try {
      KeysetHandle unused = CleartextKeysetHandle.parseFrom(proto);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "invalid keyset");
    }

    try {
      KeysetHandle unused = CleartextKeysetHandle.parseFrom(new ByteArrayInputStream(proto));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "invalid keyset");
    }
  }

  @Test
  public void testVoidInputs() throws Exception {
    KeysetHandle unused;

    try {
      unused = CleartextKeysetHandle.parseFrom(new ByteArrayInputStream(new byte[0]));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    try {
      unused = CleartextKeysetHandle.parseFrom(new byte[0]);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    try {
      unused = CleartextKeysetHandle.parseFrom((ByteArrayInputStream) null);
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }
  }
}
