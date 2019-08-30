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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.StreamingTestUtil;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKey;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingKeyFormat;
import com.google.crypto.tink.proto.AesGcmHkdfStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for AesGcmHkdfStreamingKeyManager. */
@RunWith(JUnit4.class)
public class AesGcmHkdfStreamingKeyManagerTest {
  private final AesGcmHkdfStreamingKeyManager manager = new AesGcmHkdfStreamingKeyManager();
  private final AesGcmHkdfStreamingKeyManager.KeyFactory<
          AesGcmHkdfStreamingKeyFormat, AesGcmHkdfStreamingKey>
      factory = manager.keyFactory();

  private static AesGcmHkdfStreamingKeyFormat createKeyFormat(
      int keySize, int derivedKeySize, HashType hashType, int segmentSize) {
    return AesGcmHkdfStreamingKeyFormat.newBuilder()
        .setKeySize(keySize)
        .setParams(
            AesGcmHkdfStreamingParams.newBuilder()
                .setDerivedKeySize(derivedKeySize)
                .setHkdfHashType(hashType)
                .setCiphertextSegmentSize(segmentSize))
        .build();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat_empty_throws() throws Exception {
    try {
      factory.validateKeyFormat(AesGcmHkdfStreamingKeyFormat.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    factory.validateKeyFormat(createKeyFormat(32, 32, HashType.SHA256, 1024));
  }

  @Test
  public void validateKeyFormat_unkownHash_throws() throws Exception {
    try {
      factory.validateKeyFormat(createKeyFormat(32, 32, HashType.UNKNOWN_HASH, 1024));
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_smallKey_throws() throws Exception {
    try {
      // TODO(b/140161847): Also check (16,32,SHA256,1024)
      factory.validateKeyFormat(createKeyFormat(15, 32, HashType.SHA256, 1024));
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_smallSegment_throws() throws Exception {
    try {
      factory.validateKeyFormat(createKeyFormat(16, 32, HashType.SHA256, 45));
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void createKey_checkValues() throws Exception {
    AesGcmHkdfStreamingKeyFormat format = createKeyFormat(32, 32, HashType.SHA256, 1024);

    AesGcmHkdfStreamingKey key = factory.createKey(format);

    assertThat(key.getParams()).isEqualTo(format.getParams());
    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getKeyValue()).hasSize(format.getKeySize());
  }

  @Test
  public void testSkip() throws Exception {
    AesGcmHkdfStreamingKey key = factory.createKey(createKeyFormat(32, 32, HashType.SHA256, 1024));
    StreamingAead streamingAead = manager.getPrimitive(key, StreamingAead.class);
    int offset = 0;
    int plaintextSize = 1 << 16;
    // Runs the test with different sizes for the chunks to skip.
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 1);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 64);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 300);
  }

  @Test
  public void testNewKeyMultipleTimes() throws Exception {
    AesGcmHkdfStreamingKeyFormat keyFormat = createKeyFormat(32, 32, HashType.SHA256, 1024);
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(TestUtil.hexEncode(factory.createKey(keyFormat).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }
}
