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
import com.google.crypto.tink.proto.AesCtrHmacStreamingKey;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat;
import com.google.crypto.tink.proto.AesCtrHmacStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
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

/** Test for AesCtrHmacStreamingKeyManager. */
@RunWith(JUnit4.class)
public class AesCtrHmacStreamingKeyManagerTest {
  private static final int AES_KEY_SIZE = 16;
  private HmacParams hmacParams;
  private AesCtrHmacStreamingParams keyParams;
  private AesCtrHmacStreamingKeyManager keyManager;

  @Before
  public void setUp() throws GeneralSecurityException {
    hmacParams = HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(16).build();
    keyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(128)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .setHmacParams(hmacParams)
            .build();
    keyManager = new AesCtrHmacStreamingKeyManager();
  }

  @Test
  public void testBasic() throws Exception {
    // Create primitive from a given key.
    AesCtrHmacStreamingKey key =
        AesCtrHmacStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(20)))
            .setParams(keyParams)
            .build();
    StreamingAead streamingAead = keyManager.getPrimitive(key);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);

    // Create a key from KeyFormat, and use the key.
    AesCtrHmacStreamingKeyFormat keyFormat =
        AesCtrHmacStreamingKeyFormat.newBuilder().setParams(keyParams).setKeySize(16).build();
    ByteString serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    key = (AesCtrHmacStreamingKey) keyManager.newKey(serializedKeyFormat);
    streamingAead = keyManager.getPrimitive(key);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    AesCtrHmacStreamingKeyFormat keyFormat =
        AesCtrHmacStreamingKeyFormat.newBuilder().setParams(keyParams).setKeySize(16).build();
    ByteString serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    Set<String> keys = new TreeSet<String>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 27;
    for (int i = 0; i < numTests / 3; i++) {
      AesCtrHmacStreamingKey key = (AesCtrHmacStreamingKey) keyManager.newKey(keyFormat);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      key = (AesCtrHmacStreamingKey) keyManager.newKey(serializedKeyFormat);
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);

      KeyData keyData = keyManager.newKeyData(serializedKeyFormat);
      key = AesCtrHmacStreamingKey.parseFrom(keyData.getValue());
      keys.add(TestUtil.hexEncode(key.getKeyValue().toByteArray()));
      assertEquals(16, key.getKeyValue().toByteArray().length);
    }
    assertEquals(numTests, keys.size());
  }

  private void testNewKeyWithBadFormat(AesCtrHmacStreamingParams badKeyParams) throws Exception {
    AesCtrHmacStreamingKeyFormat keyFormat =
        AesCtrHmacStreamingKeyFormat.newBuilder().setParams(badKeyParams).setKeySize(16).build();
    testNewKeyWithBadFormat(keyFormat);
  }

  private void testNewKeyWithBadFormat(AesCtrHmacStreamingKeyFormat keyFormat) throws Exception {
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
  }

  @Test
  public void testNewKeyWithBadFormat() throws Exception {
    // key_size too small.
    AesCtrHmacStreamingKeyFormat keyFormat =
        AesCtrHmacStreamingKeyFormat.newBuilder().setParams(keyParams).setKeySize(15).build();
    testNewKeyWithBadFormat(keyFormat);

    // Unknown HKDF HashType.
    AesCtrHmacStreamingParams badKeyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(128)
            .setDerivedKeySize(AES_KEY_SIZE)
            .build();
    testNewKeyWithBadFormat(badKeyParams);

    // derived_key_size too small.
    badKeyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(128)
            .setDerivedKeySize(10)
            .setHkdfHashType(HashType.SHA256)
            .build();
    testNewKeyWithBadFormat(badKeyParams);

    // ciphertext_segment_size too small.
    badKeyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(15)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .build();
    testNewKeyWithBadFormat(badKeyParams);

    // No HmacParams.
    badKeyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(130)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .build();
    testNewKeyWithBadFormat(badKeyParams);

    // Unknown HmacParams.hash.
    badKeyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(130)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .setHmacParams(HmacParams.newBuilder().build())
            .build();
    testNewKeyWithBadFormat(badKeyParams);

    // tag size too small.
    badKeyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(130)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .setHmacParams(
                HmacParams.newBuilder()
                    .setHash(HashType.SHA256)
                    .setTagSize(9)
                    .build())
            .build();
    testNewKeyWithBadFormat(badKeyParams);

    // tag size too big.
    badKeyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(130)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .setHmacParams(
                HmacParams.newBuilder()
                    .setHash(HashType.SHA256)
                    .setTagSize(33)
                    .build())
            .build();
    testNewKeyWithBadFormat(badKeyParams);

    // All params good.
    AesCtrHmacStreamingParams goodKeyParams =
        AesCtrHmacStreamingParams.newBuilder()
            .setCiphertextSegmentSize(130)
            .setDerivedKeySize(AES_KEY_SIZE)
            .setHkdfHashType(HashType.SHA256)
            .setHmacParams(hmacParams)
            .build();
    keyFormat =
        AesCtrHmacStreamingKeyFormat.newBuilder().setParams(goodKeyParams).setKeySize(16).build();
    ByteString serializedKeyFormat = ByteString.copyFrom(keyFormat.toByteArray());
    AesCtrHmacStreamingKey unusedKey = (AesCtrHmacStreamingKey) keyManager.newKey(keyFormat);
    unusedKey = (AesCtrHmacStreamingKey) keyManager.newKey(serializedKeyFormat);
  }

  @Test
  public void testJsonExportAndImport() throws Exception {
    AesCtrHmacStreamingKeyManager keyManager = new AesCtrHmacStreamingKeyManager();
    int keyCount = 4;

    // Prepare example formats and keys.
    ByteString[] formats = new ByteString[keyCount];
    formats[0] = StreamingAeadKeyTemplates.AES128_CTR_HMAC_SHA256_4KB.getValue();
    formats[1] = StreamingAeadKeyTemplates.AES256_CTR_HMAC_SHA256_4KB.getValue();
    formats[2] = StreamingAeadKeyTemplates.createAesCtrHmacStreamingKeyTemplate(
        48, HashType.SHA224, 32, HashType.SHA512, 16, 8192).getValue();
    formats[3] = StreamingAeadKeyTemplates.createAesCtrHmacStreamingKeyTemplate(
        32, HashType.SHA512, 32, HashType.SHA256, 24, 16384).getValue();

    AesCtrHmacStreamingKey[] keys = new AesCtrHmacStreamingKey[keyCount];
    for (int i = 0; i < keyCount; i++) {
      try {
        keys[i] = (AesCtrHmacStreamingKey) keyManager.newKey(formats[i]);
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for formats[" + i + "]:\n"
            + AesCtrHmacStreamingKeyFormat.parseFrom(formats[i]).toString());
      }
    }

    // Check export and import of keys.
    int count = 0;
    for (AesCtrHmacStreamingKey key : keys) {
      try {
        byte[] json = keyManager.keyToJson(key.toByteString());
        AesCtrHmacStreamingKey keyFromJson = (AesCtrHmacStreamingKey) keyManager.jsonToKey(json);
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
        AesCtrHmacStreamingKeyFormat formatFromJson =
            (AesCtrHmacStreamingKeyFormat) keyManager.jsonToKeyFormat(json);
        assertEquals(AesCtrHmacStreamingKeyFormat.parseFrom(format).toString(),
            formatFromJson.toString());
        count++;
      } catch (Exception e) {
        throw new Exception(e.toString() + "\nFailed for format:\n"
            + AesCtrHmacStreamingKeyFormat.parseFrom(format).toString());
      }
    }
    assertEquals(keyCount, count);
  }

  @Test
  @SuppressWarnings("unused")  // Unused key/format/json-variables are not set unless test fails.
  public void testJsonExportAndImportErrors() throws Exception {
    AesCtrHmacStreamingKeyManager keyManager = new AesCtrHmacStreamingKeyManager();

    try {
      byte[] json = "some bad JSON key".getBytes(Util.UTF_8);
      AesCtrHmacStreamingKey key = (AesCtrHmacStreamingKey) keyManager.jsonToKey(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {
      byte[] json = "a bad JSON keyformat".getBytes(Util.UTF_8);
      AesCtrHmacStreamingKeyFormat format =
          (AesCtrHmacStreamingKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Corrupted JSON, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "text must begin");
    }

    try {  // An incomplete JSON key.
      byte[] json = "{\"version\": 0, \"params\": {}}".getBytes(Util.UTF_8);
      AesCtrHmacStreamingKey key = (AesCtrHmacStreamingKey) keyManager.jsonToKey(json);
      fail("Incomplet JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // An incomplete JSON key format.
      byte[] json = "{\"keySize\": 32}".getBytes(Util.UTF_8);
      AesCtrHmacStreamingKeyFormat format =
          (AesCtrHmacStreamingKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Incomplete JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Extra name in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"derivedKeySize\": 16}, "
          + "\"keyValue\": \"some key bytes\", \"extraName\": 42}").getBytes(Util.UTF_8);
      AesCtrHmacStreamingKey key = (AesCtrHmacStreamingKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key");
    }

    try {  // Extra name JSON key format.
      byte[] json = ("{\"params\": {\"derivedKeySize\": 16}, "
          + "\"keySize\": 16, \"extraName\": 42}").getBytes(Util.UTF_8);
      AesCtrHmacStreamingKeyFormat format =
          (AesCtrHmacStreamingKeyFormat) keyManager.jsonToKeyFormat(json);
      fail("Invalid JSON key format, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid key format");
    }

    try {  // Incomplete params in JSON key.
      byte[] json = ("{\"version\": 0, \"params\": {\"derivedKeySize\": 16}, "
          + "\"keyValue\": \"some key bytes\"}").getBytes(Util.UTF_8);
      AesCtrHmacStreamingKey key = (AesCtrHmacStreamingKey) keyManager.jsonToKey(json);
      fail("Invalid JSON key, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "JSONException");
      assertExceptionContains(e, "Invalid params");
    }

    try {  // An incomplete AesCtrHmacStreamingKey.
      AesCtrHmacStreamingKey key = AesCtrHmacStreamingKey.newBuilder().setVersion(42).build();
      byte[] json = keyManager.keyToJson(key.toByteString());
      fail("Incomplete AesCtrHmacStreamingKey, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
    }

    try {  // An incomplete AesCtrHmacStreamingKeyFormat.
      AesCtrHmacStreamingKeyFormat format =
          AesCtrHmacStreamingKeyFormat.newBuilder().setKeySize(42).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Incomplete AesCtrHmacStreamingKeyFormat, should have thrown exception");
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
      assertExceptionContains(e, "expected serialized AesCtrHmacStreamingKey");
    }

    try {  // Wrong serialized key format proto.
      KeyData format = KeyData.newBuilder()
          .setTypeUrl("some URL").setValue(ByteString.copyFromUtf8("some value")).build();
      byte[] json = keyManager.keyFormatToJson(format.toByteString());
      fail("Wrong key format proto, should have thrown exception");
    } catch (GeneralSecurityException e) {
      // Expected.
      assertExceptionContains(e, "expected serialized AesCtrHmacStreamingKeyFormat");
    }
  }
}
