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

package com.google.crypto.tink.mac.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.subtle.Hex;
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

  @Test
  public void padTooLongTest() {
    assertThrows(IllegalArgumentException.class, () -> AesUtil.cmacPad(new byte[16]));
  }

  @Test
  public void dblTestVectors() {
    // Extracted from the SIV test vectors at https://tools.ietf.org/html/rfc5297#section-2.3
    // (all the double() steps in Appendix A)
    String[] testVectorInputs = {
        "0e04dfafc1efbf040140582859bf073a",
        "edf09de876c642ee4d78bce4ceedfc4f",
        "c8b43b5974960e7ce6a5dd85231e591a",
        "adf31e285d3d1e1d4ddefc1e5bec63e9",
        "826aa75b5e568eed3125bfb266c61d4e",
    };
    String[] testVectorOutputs = {
        "1c09bf5f83df7e080280b050b37e0e74",
        "dbe13bd0ed8c85dc9af179c99ddbf819",
        "916876b2e92c1cf9cd4bbb0a463cb2b3",
        "5be63c50ba7a3c3a9bbdf83cb7d8c755",
        "04d54eb6bcad1dda624b7f64cd8c3a1b",
    };

    byte[] r;
    for (int i = 0; i < testVectorInputs.length; i++) {
      r = AesUtil.dbl(Hex.decode(testVectorInputs[i]));
      assertEquals(testVectorOutputs[i], Hex.encode(r));
    }
  }
}
