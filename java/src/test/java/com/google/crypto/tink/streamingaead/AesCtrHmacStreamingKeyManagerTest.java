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
import com.google.crypto.tink.proto.AesCtrHmacStreamingKey;
import com.google.crypto.tink.proto.AesCtrHmacStreamingKeyFormat;
import com.google.crypto.tink.proto.AesCtrHmacStreamingParams;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HmacParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for AesCtrHmacStreamingKeyManager. */
@RunWith(JUnit4.class)
public class AesCtrHmacStreamingKeyManagerTest {
  private final AesCtrHmacStreamingKeyManager manager = new AesCtrHmacStreamingKeyManager();
  private final AesCtrHmacStreamingKeyManager.KeyFactory<
          AesCtrHmacStreamingKeyFormat, AesCtrHmacStreamingKey>
      factory = manager.keyFactory();

  // Returns an HmacParams.Builder with valid parameters
  private static HmacParams.Builder createHmacParams() {
    return HmacParams.newBuilder().setHash(HashType.SHA256).setTagSize(32);
  }

  // Returns an AesCtrHmacStreamingParams.Builder with valid parameters
  private static AesCtrHmacStreamingParams.Builder createParams() {
    return AesCtrHmacStreamingParams.newBuilder()
        .setCiphertextSegmentSize(1024)
        .setDerivedKeySize(32)
        .setHkdfHashType(HashType.SHA256)
        .setHmacParams(createHmacParams());
  }

  // Returns an AesCtrHmacStreamingKeyFormat.Builder with valid parameters
  private static AesCtrHmacStreamingKeyFormat.Builder createKeyFormat() {
    return AesCtrHmacStreamingKeyFormat.newBuilder().setKeySize(32).setParams(createParams());
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKeyFormat_empty_throws() throws Exception {
    try {
      factory.validateKeyFormat(AesCtrHmacStreamingKeyFormat.getDefaultInstance());
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_valid() throws Exception {
    AesCtrHmacStreamingKeyFormat format = createKeyFormat().build();

    factory.validateKeyFormat(format);
  }

  @Test
  public void validateKeyFormat_derivedKeySizes() throws Exception {
    for (int derivedKeySize = 0; derivedKeySize < 42; ++derivedKeySize) {
      AesCtrHmacStreamingKeyFormat format =
          createKeyFormat().setParams(createParams().setDerivedKeySize(derivedKeySize)).build();
      if (derivedKeySize == 16 || derivedKeySize == 32) {
        factory.validateKeyFormat(format);
      } else {
        try {
          factory.validateKeyFormat(format);
          fail();
        } catch (GeneralSecurityException e) {
          // expected
        }
      }
    }
  }

  @Test
  public void validateKeyFormat_smallKey_throws() throws Exception {
    // TODO(b/140161847): Also check for key size 16.
    AesCtrHmacStreamingKeyFormat format = createKeyFormat().setKeySize(15).build();
    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_unkownHash_throws() throws Exception {
    AesCtrHmacStreamingKeyFormat format =
        createKeyFormat().setParams(createParams().setHkdfHashType(HashType.UNKNOWN_HASH)).build();
    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_unkownHmacHash_throws() throws Exception {
    AesCtrHmacStreamingKeyFormat format =
        createKeyFormat()
            .setParams(
                createParams().setHmacParams(createHmacParams().setHash(HashType.UNKNOWN_HASH)))
            .build();
    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_smallSegment_throws() throws Exception {
    AesCtrHmacStreamingKeyFormat format =
        createKeyFormat().setParams(createParams().setCiphertextSegmentSize(45)).build();

    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_tagSizeTooBigSha1_throws() throws Exception {
    AesCtrHmacStreamingKeyFormat format =
        createKeyFormat()
            .setParams(
                createParams()
                    .setHmacParams(createHmacParams().setHash(HashType.SHA1).setTagSize(21)))
            .build();

    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_tagSizeTooBigSha256_throws() throws Exception {
    AesCtrHmacStreamingKeyFormat format =
        createKeyFormat()
            .setParams(
                createParams()
                    .setHmacParams(createHmacParams().setHash(HashType.SHA256).setTagSize(33)))
            .build();

    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void validateKeyFormat_tagSizeTooBigSha512_throws() throws Exception {
    AesCtrHmacStreamingKeyFormat format =
        createKeyFormat()
            .setParams(
                createParams()
                    .setHmacParams(createHmacParams().setHash(HashType.SHA512).setTagSize(65)))
            .build();

    try {
      factory.validateKeyFormat(format);
      fail();
    } catch (GeneralSecurityException e) {
      // expected
    }
  }

  @Test
  public void createKey_values() throws Exception {
    AesCtrHmacStreamingKeyFormat format = createKeyFormat().build();
    AesCtrHmacStreamingKey key = factory.createKey(format);
    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getKeyValue()).hasSize(format.getKeySize());
    assertThat(key.getParams()).isEqualTo(format.getParams());
  }

  @Test
  public void testSkip() throws Exception {
    AesCtrHmacStreamingKeyFormat format = createKeyFormat().build();
    AesCtrHmacStreamingKey key = factory.createKey(format);
    StreamingAead streamingAead = manager.getPrimitive(key, StreamingAead.class);
    int offset = 0;
    int plaintextSize = 1 << 16;
    // Runs the test with different sizes for the chunks to skip.
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 1);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 64);
    StreamingTestUtil.testSkipWithStream(streamingAead, offset, plaintextSize, 300);
  }

  @Test
  public void createKey_multipleTimes_differentValues() throws Exception {
    AesCtrHmacStreamingKeyFormat keyFormat = createKeyFormat().build();
    Set<String> keys = new TreeSet<>();
    // Calls newKey multiple times and make sure that they generate different keys.
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(TestUtil.hexEncode(factory.createKey(keyFormat).getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }
}
