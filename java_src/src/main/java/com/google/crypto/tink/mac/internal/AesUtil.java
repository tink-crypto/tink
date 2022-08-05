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

import java.util.Arrays;

/**
 * A collection of byte-manipulation functions, and some more specific functions for AES-CMAC /
 * AES-SIV.
 *
 * <p>Beware: some of the functions here are specific to the representation used for AES-CMAC and
 * SIV, as described in their RFCs. These might not work if used in other contexts.
 */
public final class AesUtil {

  public static final int BLOCK_SIZE = 16;

  /**
   * Multiplies value by x in the finite field GF(2^128) represented using the primitive polynomial
   * x^128 + x^7 + x^2 + x + 1.
   *
   * @param value an arrays of 16 bytes representing an element of GF(2^128) using bigendian byte
   * order.
   */
  public static byte[] dbl(final byte[] value) {
    if (value.length != BLOCK_SIZE) {
      throw new IllegalArgumentException("value must be a block.");
    }

    // Note that >> is an arithmetical shift, which copies the leftmost bit to fill the
    // blanks created by shifting. For instance, x >> 7 will equal 0xFF if (x & 1), and 0x00
    // otherwise. This is a bit hard to read, but the operation is branchless, which is valuable
    // in this context.

    // Shift left by one.
    byte[] res = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
      res[i] = (byte) (0xFE & (value[i] << 1));
      if (i < BLOCK_SIZE - 1) {
        res[i] |= (byte) (0x01 & (value[i + 1] >> 7));
      }
    }
    // And handle the modulus if needed (0x87 is the binary representation of the polynomial,
    // minus the x^128 part).
    res[BLOCK_SIZE - 1] ^= (byte) (0x87 & (value[0] >> 7));
    return res;
  }

  /**
   * Pad by adding a 1 bit, then pad with 0 bits to the next block limit. This is the standard for
   * both CMAC and AES-SIV. - https://tools.ietf.org/html/rfc4493#section-2.4 -
   * https://tools.ietf.org/html/rfc5297#section-2.1
   *
   * @param x The array to pad (will be copied)
   * @return The padded array.
   */
  public static byte[] cmacPad(final byte[] x) {
    if (x.length >= BLOCK_SIZE) {
      throw new IllegalArgumentException("x must be smaller than a block.");
    }
    byte[] result = Arrays.copyOf(x, 16);
    result[x.length] = (byte) 0x80;
    return result;
  }

  private AesUtil() {}
}
