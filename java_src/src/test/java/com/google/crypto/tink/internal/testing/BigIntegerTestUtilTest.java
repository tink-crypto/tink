// Copyright 2023 Google LLC
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

package com.google.crypto.tink.internal.testing;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class BigIntegerTestUtilTest {

  @Test
  public void ensureLeadingZeroBit_bitNotSet_works() throws Exception {
    // 258 = 1 * 256 + 2.
    // If the most significant bit is not set, there is no leading zero.
    byte[] encodingOf258 = new byte[] {(byte) 1, (byte) 2};

    assertThat(BigIntegerTestUtil.ensureLeadingZeroBit(encodingOf258)).isEqualTo(encodingOf258);
  }

  @Test
  public void ensureLeadingZeroBit_bitSet_works() throws Exception {
    // If the most significant bit is set, then a leading zero is added.
    byte[] encodingOf255 = new byte[] {(byte) 0xff};
    byte[] twoComplementEncodingOf255 = new byte[] {(byte) 0, (byte) 0xff};

    assertThat(BigIntegerTestUtil.ensureLeadingZeroBit(encodingOf255))
        .isEqualTo(twoComplementEncodingOf255);
  }
}
