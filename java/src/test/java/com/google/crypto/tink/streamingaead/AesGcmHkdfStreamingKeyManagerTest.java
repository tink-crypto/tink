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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.StreamingTestUtil;
import com.google.crypto.tink.TestUtil;
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
  public void testSkip() throws Exception {
    AesGcmHkdfStreamingKey key =
        AesGcmHkdfStreamingKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(20)))
            .setParams(keyParams)
            .build();
    StreamingAead streamingAead = keyManager.getPrimitive(key);
    int offset = 0;
    int plaintextSize = 1 << 16;
    // Runs the test with different sizes for the chunks to skip.
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 1);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 64);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 300);
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
}
