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

import com.google.crypto.tink.Config;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.AesCtrHmacAeadKey;
import com.google.crypto.tink.proto.AesCtrHmacAeadKeyFormat;
import com.google.crypto.tink.proto.AesCtrKeyFormat;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AesCtrHmaAeadKeyManager. */
@RunWith(JUnit4.class)
public class AesCtrHmacAeadKeyManagerTest {
  @BeforeClass
  public static void setUp() throws Exception {
    Config.register(AeadConfig.TINK_1_0_0);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    KeyTemplate keyTemplate = AeadKeyTemplates.AES128_CTR_HMAC_SHA256;
    AesCtrHmacAeadKeyFormat aeadKeyFormat =
        AesCtrHmacAeadKeyFormat.parseFrom(keyTemplate.getValue().toByteArray());
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
    KeyTemplate keyTemplate =
        KeyTemplate.newBuilder()
            .setTypeUrl(AesCtrHmacAeadKeyManager.TYPE_URL)
            .setValue(serialized)
            .build();
    AesCtrHmacAeadKeyManager keyManager = new AesCtrHmacAeadKeyManager();
    try {
      keyManager.newKey(serialized);
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected.
    }
    try {
      keyManager.newKeyData(keyTemplate.getValue());
      fail("Corrupted format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected.
    }
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    AesCtrHmacAeadKeyManager keyManager = new AesCtrHmacAeadKeyManager();
    int keyCount = 4;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = AeadKeyTemplates.AES128_CTR_HMAC_SHA256.getValue();
    formats[1] = AeadKeyTemplates.AES256_CTR_HMAC_SHA256.getValue();
    formats[2] = AeadKeyTemplates
        .createAesCtrHmacAeadKeyTemplate(24, 16, 16, 32, HashType.SHA512).getValue();
    formats[3] = AeadKeyTemplates
        .createAesCtrHmacAeadKeyTemplate(16, 12, 32, 16, HashType.SHA1).getValue();

    AesCtrHmacAeadKey[] keys = new AesCtrHmacAeadKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (AesCtrHmacAeadKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString()
            + "\nFailed for formats[" + i + "]: " + formats[i].toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (AesCtrHmacAeadKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        AesCtrHmacAeadKey keyFromJson = (AesCtrHmacAeadKey) keyManager.jsonToKey(json);
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
        AesCtrHmacAeadKeyFormat formatFromJson =
            (AesCtrHmacAeadKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(AesCtrHmacAeadKeyFormat.parseFrom(format).toString(),
            formatFromJson.toString());
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format: " + format.toString());
      }
      count++;
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    AesCtrHmacAeadKeyManager keyManager = new AesCtrHmacAeadKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      AesCtrHmacAeadKey key = (AesCtrHmacAeadKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      AesCtrHmacAeadKeyFormat format = (AesCtrHmacAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = ("{\"version\": 0, \"aesCtrKey\": {\"someName\": 42}}").getBytes(Util.UTF_8);
      AesCtrHmacAeadKey key = (AesCtrHmacAeadKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = ("{\"aesCtrKeyFormat\": {\"someName\": 42}}").getBytes(Util.UTF_8);
      AesCtrHmacAeadKeyFormat format = (AesCtrHmacAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"aesCtrKey\": {\"someName\": 42}, "
          + "\"hmacKey\": {\"someName\": 42}, \"extraName\": 42}").getBytes(Util.UTF_8);
      AesCtrHmacAeadKey key = (AesCtrHmacAeadKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"aesCtrKeyFormat\": {\"someName\": 42}, "
          + "\"hmacKeyFormat\": {\"someName\": 42}, \"extraName\": 42}").getBytes(Util.UTF_8);
      AesCtrHmacAeadKeyFormat format = (AesCtrHmacAeadKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // An incomplete AesCtrHmacAeadKey.
      AesCtrHmacAeadKey key = AesCtrHmacAeadKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete AesCtrHmacAeadKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete AesCtrHmacAeadKeyFormat.
      AesCtrHmacAeadKeyFormat format = AesCtrHmacAeadKeyFormat.newBuilder()
          .setAesCtrKeyFormat(AesCtrKeyFormat.newBuilder().setKeySize(42).build()).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete AesCtrHmacAeadKeyFormat, should have thrown exception");
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
      assertExceptionContains(e, "expected serialized AesCtrHmacAeadKey");
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized AesCtrHmacAeadKeyFormat");
    }
  }
}
