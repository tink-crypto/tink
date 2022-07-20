// Copyright 2021 Google LLC
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

package com.google.crypto.tink.aead.internal;

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.testing.TestUtil;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link ChaCha20Util}. */
@RunWith(JUnit4.class)
public final class ChaCha20UtilTest {
  /** https://tools.ietf.org/html/rfc7539#section-2.1.1 */
  @Test
  public void testQuarterRound() {
    int[] x = TestUtil.twoCompInt(new long[] {0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567});
    ChaCha20Util.quarterRound(x, 0, 1, 2, 3);
    assertThat(x)
        .isEqualTo(
            TestUtil.twoCompInt(new long[] {0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb}));
  }

  /** https://tools.ietf.org/html/rfc7539#section-2.2.1 */
  @Test
  public void testQuarterRound16() {
    int[] x =
        TestUtil.twoCompInt(
            new long[] {
              0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
              0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
              0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
              0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
            });
    ChaCha20Util.quarterRound(x, 2, 7, 8, 13);
    assertThat(x)
        .isEqualTo(
            TestUtil.twoCompInt(
                new long[] {
                  0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
                  0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
                  0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
                  0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
                }));
  }

  /** https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.2 */
  @Test
  public void testSetSigmaAndKey() {
    int[] key =
        TestUtil.twoCompInt(
            new long[] {
              0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
              0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
            });
    int[] state = new int[ChaCha20Util.BLOCK_SIZE_IN_INTS];
    ChaCha20Util.setSigmaAndKey(state, key);
    // Verify that first four words equal ChaCha20Util.SIGMA.
    assertThat(Arrays.copyOf(state, 4))
        .isEqualTo(
            TestUtil.twoCompInt(new long[] {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}));
    // Verify that next eight words equal key.
    assertThat(Arrays.copyOfRange(state, 4, 12)).isEqualTo(key);
  }
}
