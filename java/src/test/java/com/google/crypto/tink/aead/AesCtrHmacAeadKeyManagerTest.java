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

package com.google.crypto.tink.aead;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.fail;

import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests for AesCtrHmaAeadKeyManager.
 */
@RunWith(JUnit4.class)
public class AesCtrHmacAeadKeyManagerTest {
  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    KeyTemplate keyTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    AesCtrHmacAeadKeyFormat aeadKeyFormat = AesCtrHmacAeadKeyFormat.parseFrom(
        keyTemplate.getValue().toByteArray());
    ByteString serialized = ByteString.copyFrom(aeadKeyFormat.toByteArray());
    AesCtrHmacAeadKeyManager keyManager = new AesCtrHmacAeadKeyManager();
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 24;
    for (int i = 0; i < numTests / 6; i++) {
      AesCtrHmacAeadKey key = (AesCtrHmacAeadKey) keyManager.newKey(aeadKeyFormat);
      keys.add(new String(key.getAesCtrKey().getKeyValue().toByteArray(), "UTF-8"));
      keys.add(new String(key.getHmacKey().getKeyValue().toByteArray(), "UTF-8"));
      assertEquals(16, key.getAesCtrKey().getKeyValue().toByteArray().length);
      assertEquals(32, key.getHmacKey().getKeyValue().toByteArray().length);

      key = (AesCtrHmacAeadKey) keyManager.newKey(serialized);
      keys.add(new String(key.getAesCtrKey().getKeyValue().toByteArray(), "UTF-8"));
      keys.add(new String(key.getHmacKey().getKeyValue().toByteArray(), "UTF-8"));
      assertEquals(16, key.getAesCtrKey().getKeyValue().toByteArray().length);
      assertEquals(32, key.getHmacKey().getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
      key = AesCtrHmacAeadKey.parseFrom(keyData.getValue());
      keys.add(new String(key.getAesCtrKey().getKeyValue().toByteArray(), "UTF-8"));
      keys.add(new String(key.getHmacKey().getKeyValue().toByteArray(), "UTF-8"));
      assertEquals(16, key.getAesCtrKey().getKeyValue().toByteArray().length);
      assertEquals(32, key.getHmacKey().getKeyValue().toByteArray().length);
    }
    assertEquals(numTests, keys.size());
  }

  @Test
  public void testNewKeyWithCorruptedFormat() throws Exception {
    ByteString serialized = ByteString.copyFrom(new byte[128]);
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl(AesCtrHmacAeadKeyManager.TYPE_URL)
        .setValue(serialized)
        .build();
    AesCtrHmacAeadKeyManager keyManager = new AesCtrHmacAeadKeyManager();
    try {
      keyManager.newKey(serialized);
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      keyManager.newKeyData(keyTemplate.getValue());
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
  }
}
