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

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacKey;
import com.google.crypto.tink.proto.HmacKeyFormat;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData;
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

  @Test
  public void testJsonExportAndImport() throws Exception {
    HmacKeyManager keyManager = new HmacKeyManager();
    int keyCount = 4;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = MacKeyTemplates.HMAC_SHA256_128BITTAG.getValue();
    formats[1] = MacKeyTemplates.HMAC_SHA256_128BITTAG.getValue();
    formats[2] = MacKeyTemplates.createHmacKeyTemplate(32, 64, HashType.SHA512).getValue();
    formats[3] = MacKeyTemplates.createHmacKeyTemplate(16, 10, HashType.SHA1).getValue();

    HmacKey[] keys = new HmacKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (HmacKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for formats[" + i + "]:\n"
            + HmacKeyFormat.parseFrom(formats[i]).toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (HmacKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        HmacKey keyFromJson = (HmacKey) keyManager.jsonToKey(json);
        assertEquals(key.toString(), keyFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for key: " + key.toString());
      }
      count++;
    }
    assertEquals(keyCount, count);

    // Check export and import of key formats.
    count = 0;
    for (ByteString format : formats) {
      try {
        byte[] json = keyManager.keyFormatToJson(format);
        HmacKeyFormat formatFromJson = (HmacKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(HmacKeyFormat.parseFrom(format).toString(), formatFromJson.toString());
        count++;
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format:\n"
            + HmacKeyFormat.parseFrom(format).toString());
      }
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    HmacKeyManager keyManager = new HmacKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      HmacKey key = (HmacKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      HmacKeyFormat format = (HmacKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"params\": {\"tagSize\": 16, \"hash\": \"SHA256\"}}".getBytes(Util.UTF_8);
      HmacKey key = (HmacKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = "{\"params\": {\"tagSize\": 16, \"hash\": \"SHA256\"}}".getBytes(Util.UTF_8);
      HmacKeyFormat format = (HmacKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"tagSize\": 16, \"hash\": \"SHA256\"}, "
          + "\"keyValue\": \"some key bytes\", \"extraName\": 42}").getBytes(Util.UTF_8);
      HmacKey key = (HmacKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"params\": {\"tagSize\": 16, \"hash\": \"SHA256\"}, "
          + "\"keySize\": 16, \"extraName\": 42}").getBytes(Util.UTF_8);
      HmacKeyFormat format = (HmacKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Incomplete params in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"tagSize\": 16}, "
          + "\"keyValue\": \"some key bytes\"}").getBytes(Util.UTF_8);
      HmacKey key = (HmacKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // Extra name in JSON key params.
      byte[] json = ("{\"params\": {\"tagSize\": 16, \"hash\": \"SHA256\", \"extraName\": 42}, "
          + "\"keyValue\": \"some key bytes\", \"version\": 0}").getBytes(Util.UTF_8);
      HmacKey key = (HmacKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // An incomplete HmacKey.
      HmacKey key = HmacKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete HmacKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete HmacKeyFormat.
      HmacKeyFormat format = HmacKeyFormat.newBuilder().setKeySize(42).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete HmacKeyFormat, should have thrown exception");
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
      assertExceptionContains(e, "expected serialized HmacKey");
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized HmacKeyFormat");
    }
  }
}
