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
import static org.junit.Assert.fail;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.StreamingTestUtil;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.subtle.Random;
import java.io.IOException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests which run the everything for the Streaming Aeads. */
@RunWith(JUnit4.class)
public class StreamingAeadIntegrationTest {
  private static final int KDF_KEY_SIZE = 16;
  private static final int AES_KEY_SIZE = 16;

  @BeforeClass
  public static void setUp() throws Exception {
    StreamingAeadConfig.register();
  }

  @Test
  public void testBasicAesCtrHmacStreamingAead() throws Exception {
    byte[] keyValue = Random.randBytes(KDF_KEY_SIZE);
    int derivedKeySize = AES_KEY_SIZE;
    int ciphertextSegmentSize = 128;
    KeysetHandle keysetHandle =
        TestUtil.createKeysetHandle(
            TestUtil.createKeyset(
                TestUtil.createKey(
                    TestUtil.createAesCtrHmacStreamingKeyData(
                        keyValue, derivedKeySize, ciphertextSegmentSize),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.RAW)));
    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);
  }

  @Test
  public void testBasicAesGcmHkdfStreamingAead() throws Exception {
    byte[] keyValue = Random.randBytes(KDF_KEY_SIZE);
    int derivedKeySize = AES_KEY_SIZE;
    int ciphertextSegmentSize = 128;
    KeysetHandle keysetHandle =
        TestUtil.createKeysetHandle(
            TestUtil.createKeyset(
                TestUtil.createKey(
                    TestUtil.createAesGcmHkdfStreamingKeyData(
                        keyValue, derivedKeySize, ciphertextSegmentSize),
                    42,
                    KeyStatusType.ENABLED,
                    OutputPrefixType.RAW)));
    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead);
  }


  @Test
  public void testMultipleKeys() throws Exception {
    byte[] primaryKeyValue = Random.randBytes(KDF_KEY_SIZE);
    byte[] otherKeyValue = Random.randBytes(KDF_KEY_SIZE);
    byte[] anotherKeyValue = Random.randBytes(KDF_KEY_SIZE);
    int derivedKeySize = AES_KEY_SIZE;

    Key primaryKey = TestUtil.createKey(
        TestUtil.createAesGcmHkdfStreamingKeyData(
            primaryKeyValue, derivedKeySize, 512),
        42,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    // Another key with a smaller segment size than the primary key
    Key otherKey = TestUtil.createKey(
        TestUtil.createAesCtrHmacStreamingKeyData(
            otherKeyValue, derivedKeySize, 256),
        43,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);
    // Another key with a larger segment size than the primary key
    Key anotherKey = TestUtil.createKey(
        TestUtil.createAesGcmHkdfStreamingKeyData(
            anotherKeyValue, derivedKeySize, 1024),
        72,
        KeyStatusType.ENABLED,
        OutputPrefixType.RAW);

    KeysetHandle keysetHandle =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(primaryKey, otherKey, anotherKey));
    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

    StreamingAead primaryAead =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(primaryKey))
            .getPrimitive(StreamingAead.class);
    StreamingAead otherAead =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(otherKey))
            .getPrimitive(StreamingAead.class);
    StreamingAead anotherAead =
        TestUtil.createKeysetHandle(TestUtil.createKeyset(anotherKey))
            .getPrimitive(StreamingAead.class);

    StreamingTestUtil.testEncryptionAndDecryption(streamingAead, streamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(streamingAead, primaryAead);
    StreamingTestUtil.testEncryptionAndDecryption(primaryAead, streamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(otherAead, streamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(anotherAead, streamingAead);
    StreamingTestUtil.testEncryptionAndDecryption(primaryAead, primaryAead);
    StreamingTestUtil.testEncryptionAndDecryption(otherAead, otherAead);
    StreamingTestUtil.testEncryptionAndDecryption(anotherAead, anotherAead);
    try {
      StreamingTestUtil.testEncryptionAndDecryption(otherAead, primaryAead);
      fail("No matching key, should have thrown an exception");
    } catch (IOException expected) {
      assertExceptionContains(expected, "No matching key");
    }
    try {
      StreamingTestUtil.testEncryptionAndDecryption(anotherAead, primaryAead);
      fail("No matching key, should have thrown an exception");
    } catch (IOException expected) {
      assertExceptionContains(expected, "No matching key");
    }
  }
}
