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

package com.google.crypto.tink.streamingaead;

import static com.google.crypto.tink.TestUtil.assertExceptionContains;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.StreamingTestUtil;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.Util;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.subtle.Random;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for AesGcmHkdfStreamingKeyManager. */
@RunWith(JUnit4.class)
public class AesGcmHkdfStreamingKeyManagerTest {
  private static final int AES_KEY_SIZE = 16;
  private AesGcmHkdfStreamingParams keyParams;
  private AesGcmHkdfStreamingKeyManager keyManager;

  @Before
  public void setUp() throws GeneralSecurityException {
    keyParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(128)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .build();
    keyManager = new AesGcmHkdfStreamingKeyManager();
  }

  @Test
  public void testBasic() throws Exception {
    // Create primitive from a given key.
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(20)))
            .setParams(keyParams)
            .build();
    StreamingAead streamingAead = keyManager.getPrimitive(key);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);

    // Create a key from KeyFormat, and use the key.
    AesGcmHkdfStreamingKeyFormat keyFormat =
        AesGcmHkdfStreamingKeyFormat.newBuilder().setParams(keyParams).setKeySize(16).build();
    ByteString serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    key = (AesGcmHkdfStreamingKey) keyManager.newKey(serializedKeyFormat);
    streamingAead = keyManager.getPrimitive(key);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    AesGcmHkdfStreamingKeyFormat keyFormat =
        AesGcmHkdfStreamingKeyFormat.newBuilder().setParams(keyParams).setKeySize(16).build();
    ByteString serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 27;
    for (int i = 0; i < numTests / 3; i++) {
      AesGcmHkdfStreamingKey key = (AesGcmHkdfStreamingKey) keyManager.newKey(keyFormat);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      key = (AesGcmHkdfStreamingKey) keyManager.newKey(serializedKeyFormat);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(serializedKeyFormat);
      key = AesGcmHkdfStreamingKey.parseFrom(keyData.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);
    }
    assertEquals(numTests, keys.size());
  }

  @Test
  public void testNewKeyWithBadFormat() throws Exception {
    // key_size too small.
    AesGcmHkdfStreamingKeyFormat keyFormat =
        AesGcmHkdfStreamingKeyFormat.newBuilder().setParams(keyParams).setKeySize(15).build();
    ByteString serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    try {
      keyManager.newKey(keyFormat);
      fail("Bad format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      keyManager.newKeyData(serializedKeyFormat);
      fail("Bad format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }

    // Unknown HKDF HashType.
    AesGcmHkdfStreamingParams badKeyParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(128)
            .setDerivedKeySize(AES_KEY_SIZE)
            .build();
    keyFormat =
        AesGcmHkdfStreamingKeyFormat.newBuilder().setParams(badKeyParams).setKeySize(16).build();
    serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    try {
      keyManager.newKey(keyFormat);
      fail("Bad format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      keyManager.newKeyData(serializedKeyFormat);
      fail("Bad format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }

    // derived_key_size too small.
    badKeyParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(128)
            .setDerivedKeySize(10)
            .setHkdfHashType(HashType.SHA256)
            .build();
    keyFormat =
        AesGcmHkdfStreamingKeyFormat.newBuilder().setParams(badKeyParams).setKeySize(16).build();
    serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    try {
      keyManager.newKey(keyFormat);
      fail("Bad format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      keyManager.newKeyData(serializedKeyFormat);
      fail("Bad format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }

    // ciphertext_segment_size too small.
    badKeyParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(15)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .build();
    keyFormat =
        AesGcmHkdfStreamingKeyFormat.newBuilder().setParams(badKeyParams).setKeySize(16).build();
    serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    try {
      keyManager.newKey(keyFormat);
      fail("Bad format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }
    try {
      keyManager.newKeyData(serializedKeyFormat);
      fail("Bad format, should have thrown exception");
    } catch (GeneralSecurityException expected) {
      // Expected
    }

    // All params good.
    AesGcmHkdfStreamingParams goodKeyParams =
        AesGcmHkdfStreamingParams.newBuilder()
            .setCiphertextSegmentSize(130)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .build();
    keyFormat =
        AesGcmHkdfStreamingKeyFormat.newBuilder().setParams(goodKeyParams).setKeySize(16).build();
    serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    AesGcmHkdfStreamingKey unusedKey = (AesGcmHkdfStreamingKey) keyManager.newKey(keyFormat);
    unusedKey = (AesGcmHkdfStreamingKey) keyManager.newKey(serializedKeyFormat);
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    AesGcmHkdfStreamingKeyManager keyManager = new AesGcmHkdfStreamingKeyManager();
    int keyCount = 4;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = StreamingAeadKeyTemplates.AES128_GCM_HKDF_4KB.getValue();
    formats[1] = StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB.getValue();
    formats[2] = StreamingAeadKeyTemplates.createAesGcmHkdfStreamingKeyTemplate(
        48, HashType.SHA224, 32, 8192).getValue();
    formats[3] = StreamingAeadKeyTemplates.createAesGcmHkdfStreamingKeyTemplate(
        32, HashType.SHA512, 24, 16384).getValue();

    AesGcmHkdfStreamingKey[] keys = new AesGcmHkdfStreamingKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (AesGcmHkdfStreamingKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for formats[" + i + "]:\n"
            + AesGcmHkdfStreamingKeyFormat.parseFrom(formats[i]).toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (AesGcmHkdfStreamingKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        AesGcmHkdfStreamingKey keyFromJson = (AesGcmHkdfStreamingKey) keyManager.jsonToKey(json);
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
        AesGcmHkdfStreamingKeyFormat formatFromJson =
            (AesGcmHkdfStreamingKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(AesGcmHkdfStreamingKeyFormat.parseFrom(format).toString(),
            formatFromJson.toString());
        count++;
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format:\n"
            + AesGcmHkdfStreamingKeyFormat.parseFrom(format).toString());
      }
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    AesGcmHkdfStreamingKeyManager keyManager = new AesGcmHkdfStreamingKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      AesGcmHkdfStreamingKey key = (AesGcmHkdfStreamingKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      AesGcmHkdfStreamingKeyFormat format =
          (AesGcmHkdfStreamingKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0, \"params\": {}}".getBytes(Util.UTF_8);
      AesGcmHkdfStreamingKey key = (AesGcmHkdfStreamingKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = "{\"keySize\": 32}".getBytes(Util.UTF_8);
      AesGcmHkdfStreamingKeyFormat format =
          (AesGcmHkdfStreamingKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"derivedKeySize\": 16}, "
          + "\"keyValue\": \"some key bytes\", \"extraName\": 42}").getBytes(Util.UTF_8);
      AesGcmHkdfStreamingKey key = (AesGcmHkdfStreamingKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"params\": {\"derivedKeySize\": 16}, "
          + "\"keySize\": 16, \"extraName\": 42}").getBytes(Util.UTF_8);
      AesGcmHkdfStreamingKeyFormat format =
          (AesGcmHkdfStreamingKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Incomplete params in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"derivedKeySize\": 16}, "
          + "\"keyValue\": \"some key bytes\"}").getBytes(Util.UTF_8);
      AesGcmHkdfStreamingKey key = (AesGcmHkdfStreamingKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // An incomplete AesGcmHkdfStreamingKey.
      AesGcmHkdfStreamingKey key = AesGcmHkdfStreamingKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete AesGcmHkdfStreamingKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete AesGcmHkdfStreamingKeyFormat.
      AesGcmHkdfStreamingKeyFormat format =
          AesGcmHkdfStreamingKeyFormat.newBuilder().setKeySize(42).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete AesGcmHkdfStreamingKeyFormat, should have thrown exception");
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
      assertExceptionContains(e, "expected serialized AesGcmHkdfStreamingKey");
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized AesGcmHkdfStreamingKeyFormat");
    }
  }
}
