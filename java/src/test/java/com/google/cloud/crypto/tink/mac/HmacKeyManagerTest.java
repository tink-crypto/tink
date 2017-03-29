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

package com.google.cloud.crypto.tink.mac;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.fail;

import com.google.cloud.crypto.tink.CommonProto.HashType;
import com.google.cloud.crypto.tink.HmacProto.HmacKey;
import com.google.cloud.crypto.tink.HmacProto.HmacKeyFormat;
import com.google.cloud.crypto.tink.HmacProto.HmacParams;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link HmacKeyManager}. */
@RunWith(JUnit4.class)
public class HmacKeyManagerTest {
  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    HmacKeyManager keyManager = new HmacKeyManager();
    HmacKeyFormat hmacKeyFormat = HmacKeyFormat.newBuilder()
        .setParams(HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(16).build())
        .setKeySize(32)
        .build();
    ByteString serialized = ByteString.copyFrom(hmacKeyFormat.toByteArray());
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl("type.googleapis.com/google.cloud.crypto.tink.HmacKey")
        .setValue(serialized)
        .build();
    // Calls newKey multiple times and make sure that we get different HmacKey each time.
    Set<String> keys = new TreeSet<String>();
    int numTests = 27;
    for (int i = 0; i < numTests / 3; i++) {
      HmacKey key = keyManager.newKey(hmacKeyFormat);
      assertEquals(32, key.getKeyValue().toByteArray().length);
      keys.add(new String(key.getKeyValue().toByteArray(), "UTF-8"));

      key = keyManager.newKey(serialized);
      assertEquals(32, key.getKeyValue().toByteArray().length);
      keys.add(new String(key.getKeyValue().toByteArray(), "UTF-8"));

      key = HmacKey.parseFrom(keyManager.newKeyData(keyTemplate.getValue()).getValue());
      assertEquals(32, key.getKeyValue().toByteArray().length);
      keys.add(new String(key.getKeyValue().toByteArray(), "UTF-8"));
    }
    assertEquals(numTests, keys.size());
  }

  @Test
  public void testNewKeyCorruptedFormat() throws Exception {
    HmacKeyManager keyManager = new HmacKeyManager();
    ByteString serialized = ByteString.copyFrom(new byte[128]);
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl("type.googleapis.com/google.cloud.crypto.tink.HmacKey")
        .setValue(serialized)
        .build();
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
