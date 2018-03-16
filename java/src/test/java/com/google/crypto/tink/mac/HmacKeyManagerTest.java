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

package com.google.crypto.tink.mac;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyTemplate;
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
        .setTypeUrl(HmacKeyManager.TYPE_URL)
        .setValue(serialized)
        .build();
    // Calls newKey multiple times and make sure that we get different HmacKey each time.
    Set<String> keys = new TreeSet<String>();
    int numTests = 27;
    for (int i = 0; i < numTests / 3; i++) {
      HmacKey key = (HmacKey) keyManager.newKey(hmacKeyFormat);
      assertEquals(32, key.getKeyValue().toByteArray().length);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));

      key = (HmacKey) keyManager.newKey(serialized);
      assertEquals(32, key.getKeyValue().toByteArray().length);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));

      key = HmacKey.parseFrom(keyManager.newKeyData(keyTemplate.getValue()).getValue());
      assertEquals(32, key.getKeyValue().toByteArray().length);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
    }
    assertEquals(numTests, keys.size());
  }

  @Test
  public void testNewKeyCorruptedFormat() throws Exception {
    HmacKeyManager keyManager = new HmacKeyManager();
    ByteString serialized = ByteString.copyFrom(new byte[128]);
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl(HmacKeyManager.TYPE_URL)
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
