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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.AesCtrKey;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.AesCtrParams;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
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
        .setTypeUrl(AesCtrKeyManager.TYPE_URL)
        .setValue(serialized)
        .build();
    AesCtrKeyManager keyManager = new AesCtrKeyManager();
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 27;
    for (int i = 0; i < numTests / 3; i++) {
      AesCtrKey key = (AesCtrKey) keyManager.newKey(ctrKeyFormat);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      key = (AesCtrKey) keyManager.newKey(serialized);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(keyTemplate.getValue());
      key = AesCtrKey.parseFrom(keyData.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);
    }
    assertEquals(numTests, keys.size());
  }

  @Test
  public void testNewKeyWithCorruptedFormat() throws Exception {
    ByteString serialized = ByteString.copyFrom(new byte[128]);
    KeyTemplate keyTemplate = KeyTemplate.newBuilder()
        .setTypeUrl(AesCtrKeyManager.TYPE_URL)
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
  @Test
  public void testJsonExportAndImport() throws Exception {
    AesCtrKeyManager keyManager = new AesCtrKeyManager();
    int keyCount = 4;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(16).build())
        .setKeySize(16).build().toByteString();
    formats[1] = AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(12).build())
        .setKeySize(24).build().toByteString();
    formats[2] = AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(14).build())
        .setKeySize(32).build().toByteString();
    formats[3] = AesCtrKeyFormat.newBuilder()
        .setParams(AesCtrParams.newBuilder().setIvSize(15).build())
        .setKeySize(16).build().toByteString();

    AesCtrKey[] keys = new AesCtrKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (AesCtrKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString()
            + "\nFailed for formats[" + i + "]: " + formats[i].toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (AesCtrKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        AesCtrKey keyFromJson = (AesCtrKey) keyManager.jsonToKey(json);
        assertEquals(key.toString(), keyFromJson.toString());
        count++;
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for key: " + key.toString());
      }
    }
    assertEquals(keyCount, count);

    // Check export and import of key formats.
    count = 0;
    for (ByteString format : formats) {
      try {
        byte[] json = keyManager.keyFormatToJson(format);
        AesCtrKeyFormat formatFromJson = (AesCtrKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(AesCtrKeyFormat.parseFrom(format).toString(), formatFromJson.toString());
        count++;
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format: " + format.toString());
      }
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    AesCtrKeyManager keyManager = new AesCtrKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      AesCtrKey key = (AesCtrKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      AesCtrKeyFormat format = (AesCtrKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"params\": {\"tagSize\": 16, \"hash\": \"SHA256\"}}".getBytes(Util.UTF_8);
      AesCtrKey key = (AesCtrKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = "{\"params\": {\"tagSize\": 16, \"hash\": \"SHA256\"}}".getBytes(Util.UTF_8);
      AesCtrKeyFormat format = (AesCtrKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"ivSize\": 16}, "
          + "\"keyValue\": \"some key bytes\", \"extraName\": 42}").getBytes(Util.UTF_8);
      AesCtrKey key = (AesCtrKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"params\": {\"ivSize\": 16}, "
          + "\"keySize\": 16, \"extraName\": 42}").getBytes(Util.UTF_8);
      AesCtrKeyFormat format = (AesCtrKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Incomplete params in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"tagSize\": 16}, "
          + "\"keyValue\": \"some key bytes\"}").getBytes(Util.UTF_8);
      AesCtrKey key = (AesCtrKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // Extra name in JSON key params.
      byte[] json = ("{\"params\": {\"ivSize\": 16, \"extraName\": 42}, "
          + "\"keyValue\": \"some key bytes\", \"version\": 0}").getBytes(Util.UTF_8);
      AesCtrKey key = (AesCtrKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // An incomplete AesCtrKey.
      AesCtrKey key = AesCtrKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete AesCtrKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete AesCtrKeyFormat.
      AesCtrKeyFormat format = AesCtrKeyFormat.newBuilder().setKeySize(42).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete AesCtrKeyFormat, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // Wrong serialized key proto.
      KeyData key = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Wrong key proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized AesCtrKey");
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized AesCtrKeyFormat");
    }
  }
}
