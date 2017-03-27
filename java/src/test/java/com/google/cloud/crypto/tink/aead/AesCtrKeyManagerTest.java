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

package com.google.cloud.crypto.tink.aead;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.fail;

import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKey;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrKeyFormat;
import com.google.cloud.crypto.tink.AesCtrProto.AesCtrParams;
import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link AesCtrKeyManager}. */
@RunWith(JUnit4.class)
public class AesCtrKeyManagerTest {
  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    AesCtrKeyFormat ctrKeyFormat = AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(16).build())
        .setKeySize(16)
        .build();
    ByteString serialized = ByteString.copyFrom(ctrKeyFormat.toByteArray());
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl("type.googleapis.com/google.cloud.crypto.tink.AesCtrKey")
        .setValue(serialized)
        .build();
    AesCtrKeyManager keyManager = new AesCtrKeyManager();
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 27;
    for (int i = 0; i < numTests / 3; i++) {
      AesCtrKey key = keyManager.newKey(ctrKeyFormat);
      keys.add(new String(key.getKeyValue().toByteArray(), "UTF-8"));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      key = keyManager.newKey(serialized);
      keys.add(new String(key.getKeyValue().toByteArray(), "UTF-8"));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
      key = AesCtrKey.parseFrom(keyData.getValue());
      keys.add(new String(key.getKeyValue().toByteArray(), "UTF-8"));
      assertEquals(16, key.getKeyValue().toByteArray().length);
    }
    assertEquals(numTests, keys.size());
  }

  @Test
  public void testNewKeyWithCorruptedFormat() throws Exception {
    ByteString serialized = ByteString.copyFrom(new byte[128]);
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl("type.googleapis.com/google.cloud.crypto.tink.AesCtrKey")
        .setValue(serialized)
        .build();
    AesCtrKeyManager keyManager = new AesCtrKeyManager();
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
