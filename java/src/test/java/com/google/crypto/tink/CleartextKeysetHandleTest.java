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
import static org.junit.Assert.fail;

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.Keyset;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for CleartextKeysetHandle. */
@RunWith(JUnit4.class)
public class CleartextKeysetHandleTest {
  @BeforeClass
  public static void setUp() throws GeneralSecurityException {
    TinkConfig.register();
  }

  @Test
  public void testParse() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle = KeysetHandle.generateNew(template);
    Keyset keyset = CleartextKeysetHandle.getKeyset(handle);
    handle = CleartextKeysetHandle.parseFrom(keyset.toByteArray());
    assertEquals(keyset, handle.getKeyset());
    handle.getPrimitive(Mac.class);
  }

  @Test
  public void testRead() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetManager manager = KeysetManager.withEmptyKeyset().rotate(template);
    Keyset keyset1 = manager.getKeysetHandle().getKeyset();

    KeysetHandle handle1 =
        CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(keyset1.toByteArray()));
    assertEquals(keyset1, handle1.getKeyset());

    KeysetHandle handle2 = KeysetHandle.generateNew(template);
    Keyset keyset2 = handle2.getKeyset();
    assertEquals(1, keyset2.getKeyCount());
    Keyset.Key key2 = keyset2.getKey(0);
    assertEquals(keyset2.getPrimaryKeyId(), key2.getKeyId());
    assertEquals(template.getTypeUrl(), key2.getKeyData().getTypeUrl());
    Mac unused = handle2.getPrimitive(Mac.class);
  }

  @Test
  public void testWrite() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetHandle handle = KeysetManager.withEmptyKeyset().rotate(template).getKeysetHandle();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    KeysetWriter writer = BinaryKeysetWriter.withOutputStream(outputStream);
    CleartextKeysetHandle.write(handle, writer);
    ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
    KeysetReader reader = BinaryKeysetReader.withInputStream(inputStream);
    KeysetHandle handle2 = CleartextKeysetHandle.read(reader);
    assertEquals(handle.getKeyset(), handle2.getKeyset());
  }

  @Test
  public void testReadInvalidKeyset() throws Exception {
    // Create a keyset that contains a single HmacKey.
    KeyTemplate template = MacKeyTemplates.HMAC_SHA256_128BITTAG;
    KeysetManager manager = KeysetManager.withEmptyKeyset().rotate(template);
    Keyset keyset = manager.getKeysetHandle().getKeyset();

    byte[] proto = keyset.toByteArray();
    proto[0] = (byte) ~proto[0];
    try {
      KeysetHandle unused = CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(proto));
      fail("Expected IOException");
    } catch (IOException e) {
      // expected
    }
  }

  @Test
  public void testVoidInputs() throws Exception {
    KeysetHandle unused;

    try {
      unused = CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(new byte[0]));
      fail("Expected GeneralSecurityException");
    } catch (GeneralSecurityException e) {
      assertExceptionContains(e, "empty keyset");
    }

    try {
      unused = CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(new byte[0]));
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
  }
}
