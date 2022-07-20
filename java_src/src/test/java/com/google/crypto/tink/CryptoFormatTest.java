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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset.Key;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.testing.TestUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for CryptoFormat. */
@RunWith(JUnit4.class)
public class CryptoFormatTest {

  private Key getKey(OutputPrefixType type, int keyId) throws Exception {
    return TestUtil.createKey(
        TestUtil.createHmacKeyData("01234567890123456".getBytes(UTF_8), 16),
        keyId,
        KeyStatusType.ENABLED,
        type);
  }

  @Test
  public void testRawPrefix() throws Exception {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, 0x66AABBCC))).isEmpty();
  }

  @Test
  public void testTinkPrefix() throws Exception {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, 0x66AABBCC)))
        .isEqualTo(TestUtil.hexDecode("0166AABBCC"));
  }

  @Test
  public void testLegacyPrefix() throws Exception {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, 0x66AABBCC)))
        .isEqualTo(TestUtil.hexDecode("0066AABBCC"));
  }

  @Test
  public void testCrunchyPrefix() throws Exception {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, 0x66AABBCC)))
        .isEqualTo(TestUtil.hexDecode("0066AABBCC"));
  }

  @Test
  public void testConstants() throws Exception {
    assertThat(CryptoFormat.NON_RAW_PREFIX_SIZE).isEqualTo(5);
    assertThat(CryptoFormat.LEGACY_PREFIX_SIZE).isEqualTo(5);
    assertThat(CryptoFormat.TINK_PREFIX_SIZE).isEqualTo(5);
    assertThat(CryptoFormat.RAW_PREFIX_SIZE).isEqualTo(0);
    assertThat(CryptoFormat.RAW_PREFIX).isEmpty();
    assertThat(CryptoFormat.TINK_START_BYTE).isEqualTo(1);
    assertThat(CryptoFormat.LEGACY_START_BYTE).isEqualTo(0);
  }

  @Test
  public void testConstantsAreConsistentWithGetOutputPrefix() throws Exception {
    byte[] tinkPrefix = CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, 42));
    assertThat(tinkPrefix).hasLength(CryptoFormat.NON_RAW_PREFIX_SIZE);
    assertThat(tinkPrefix).hasLength(CryptoFormat.TINK_PREFIX_SIZE);
    assertThat(tinkPrefix[0]).isEqualTo(CryptoFormat.TINK_START_BYTE);

    byte[] legacyPrefix = CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, 42));
    assertThat(legacyPrefix).hasLength(CryptoFormat.NON_RAW_PREFIX_SIZE);
    assertThat(legacyPrefix).hasLength(CryptoFormat.LEGACY_PREFIX_SIZE);
    assertThat(legacyPrefix[0]).isEqualTo(CryptoFormat.LEGACY_START_BYTE);

    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, 42)))
        .hasLength(CryptoFormat.NON_RAW_PREFIX_SIZE);
  }

  @Test
  public void testKeyIdWithMsbSet() throws Exception {
    int keyId = 0xFF7F1058;
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, keyId)))
        .isEqualTo(TestUtil.hexDecode("01FF7F1058"));
  }

  @Test
  public void testKeyIdIsZero() throws Exception {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, 0))).isEmpty();
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, 0)))
        .isEqualTo(TestUtil.hexDecode("0100000000"));
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, 0)))
        .isEqualTo(TestUtil.hexDecode("0000000000"));
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, 0)))
        .isEqualTo(TestUtil.hexDecode("0000000000"));
  }

  @Test
  public void testKeyIdIsMinusOne() throws Exception {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, -1))).isEmpty();
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, -1)))
        .isEqualTo(TestUtil.hexDecode("01FFFFFFFF"));
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, -1)))
        .isEqualTo(TestUtil.hexDecode("00FFFFFFFF"));
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, -1)))
        .isEqualTo(TestUtil.hexDecode("00FFFFFFFF"));
  }

  @Test
  public void testKeyIdIsMaxInt() throws Exception {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, 2147483647))).isEmpty();
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, 2147483647)))
        .isEqualTo(TestUtil.hexDecode("017FFFFFFF"));
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, 2147483647)))
        .isEqualTo(TestUtil.hexDecode("007FFFFFFF"));
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, 2147483647)))
        .isEqualTo(TestUtil.hexDecode("007FFFFFFF"));
  }

  @Test
  public void testKeyIdIsMinInt() throws Exception {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, -2147483648))).isEmpty();
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, -2147483648)))
        .isEqualTo(TestUtil.hexDecode("0180000000"));
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, -2147483648)))
        .isEqualTo(TestUtil.hexDecode("0080000000"));
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, -2147483648)))
        .isEqualTo(TestUtil.hexDecode("0080000000"));
  }
}
