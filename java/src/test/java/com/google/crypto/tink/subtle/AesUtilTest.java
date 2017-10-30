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

package com.google.crypto.tink.subtle;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for AesUtil */
@RunWith(JUnit4.class)
public class AesUtilTest {

  // Some test arrays for the XOR operations.
  static final byte[] EMPTY = {};
  static final byte[] ONE_ONE = {1};

  @Test
  public void padBasicTest() {
    byte[] r = AesUtil.cmacPad(EMPTY);
    assertEquals((byte) 0x80, r[0]);
    assertEquals((byte) 0x00, r[1]);
    assertEquals((byte) 0x00, r[15]);
    assertEquals(16, r.length);

    r = AesUtil.cmacPad(ONE_ONE);
    assertEquals((byte) 0x01, r[0]);
    assertEquals((byte) 0x80, r[1]);
    assertEquals((byte) 0x00, r[2]);
    assertEquals((byte) 0x00, r[15]);
    assertEquals(16, r.length);
  }

  @Test(expected = IllegalArgumentException.class)
  public void padTooLongTest() {
    AesUtil.cmacPad(new byte[16]);
  }

  @Test
  public void dblWithLeadingZero() {
    // from the SIV test vectors
    byte[] r = AesUtil.dbl(Hex.decode("0e04dfafc1efbf040140582859bf073a"));
    assertEquals("1c09bf5f83df7e080280b050b37e0e74", Hex.encode(r));
  }

  @Test
  public void dblWithLeadingOne() {
    // from the SIV test vectors
    byte[] r = AesUtil.dbl(Hex.decode("c8b43b5974960e7ce6a5dd85231e591a"));
    assertEquals("916876b2e92c1cf9cd4bbb0a463cb2b3", Hex.encode(r));
  }
}
