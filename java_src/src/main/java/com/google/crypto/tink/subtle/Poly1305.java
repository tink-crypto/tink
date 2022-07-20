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

import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Poly1305 one-time MAC based on RFC 7539.
 *
 * <p>This is not an implementation of the MAC interface on purpose and it is not equivalent to
 * HMAC.
 *
 * <p>The implementation is based on poly1305 implementation by Andrew Moon
 * (https://github.com/floodyberry/poly1305-donna) and released as public domain.
 *
 * @deprecated replaced by {@link com.google.crypto.tink.aead.internal.Poly1305}.
 */
@Deprecated
class Poly1305 {

  public static final int MAC_TAG_SIZE_IN_BYTES = 16;
  public static final int MAC_KEY_SIZE_IN_BYTES = 32;

  private Poly1305() {}

  private static long load32(byte[] in, int idx) {
    return ((in[idx] & 0xff)
            | ((in[idx + 1] & 0xff) << 8)
            | ((in[idx + 2] & 0xff) << 16)
            | ((in[idx + 3] & 0xff) << 24))
        & 0xffffffffL;
  }

  private static long load26(byte[] in, int idx, int shift) {
    return (load32(in, idx) >> shift) & 0x3ffffff;
  }

  private static void toByteArray(byte[] output, long num, int idx) {
    for (int i = 0; i < 4; i++, num >>= 8) {
      output[idx + i] = (byte) (num & 0xff);
    }
  }

  private static void copyBlockSize(byte[] output, byte[] in, int idx) {
    int copyCount = Math.min(MAC_TAG_SIZE_IN_BYTES, in.length - idx);
    System.arraycopy(in, idx, output, 0, copyCount);
    output[copyCount] = 1;
    if (copyCount != MAC_TAG_SIZE_IN_BYTES) {
      Arrays.fill(output, copyCount + 1, output.length, (byte) 0);
    }
  }

  static byte[] computeMac(final byte[] key, byte[] data) {
    if (key.length != MAC_KEY_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("The key length in bytes must be 32.");
    }
    long h0 = 0;
    long h1 = 0;
    long h2 = 0;
    long h3 = 0;
    long h4 = 0;
    long d0;
    long d1;
    long d2;
    long d3;
    long d4;
    long c;

    // r &= 0xffffffc0ffffffc0ffffffc0fffffff
    long r0 = load26(key, 0, 0) & 0x3ffffff;
    long r1 = load26(key, 3, 2) & 0x3ffff03;
    long r2 = load26(key, 6, 4) & 0x3ffc0ff;
    long r3 = load26(key, 9, 6) & 0x3f03fff;
    long r4 = load26(key, 12, 8) & 0x00fffff;

    long s1 = r1 * 5;
    long s2 = r2 * 5;
    long s3 = r3 * 5;
    long s4 = r4 * 5;

    byte[] buf = new byte[MAC_TAG_SIZE_IN_BYTES + 1];
    for (int i = 0; i < data.length; i += MAC_TAG_SIZE_IN_BYTES) {
      copyBlockSize(buf, data, i);
      h0 += load26(buf, 0, 0);
      h1 += load26(buf, 3, 2);
      h2 += load26(buf, 6, 4);
      h3 += load26(buf, 9, 6);
      h4 += load26(buf, 12, 8) | (buf[MAC_TAG_SIZE_IN_BYTES] << 24);

      // d = r * h
      d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
      d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
      d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
      d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
      d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

      // Partial reduction mod 2^130-5, resulting h1 might not be 26bits.
      c = d0 >> 26;
      h0 = d0 & 0x3ffffff;
      d1 += c;
      c = d1 >> 26;
      h1 = d1 & 0x3ffffff;
      d2 += c;
      c = d2 >> 26;
      h2 = d2 & 0x3ffffff;
      d3 += c;
      c = d3 >> 26;
      h3 = d3 & 0x3ffffff;
      d4 += c;
      c = d4 >> 26;
      h4 = d4 & 0x3ffffff;
      h0 += c * 5;
      c = h0 >> 26;
      h0 = h0 & 0x3ffffff;
      h1 += c;
    }
    // Do final reduction mod 2^130-5
    c = h1 >> 26;
    h1 = h1 & 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 = h2 & 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 = h3 & 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 = h4 & 0x3ffffff;
    h0 += c * 5; // c * 5 can be at most 5
    c = h0 >> 26;
    h0 = h0 & 0x3ffffff;
    h1 += c;

    // Compute h - p
    long g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    long g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    long g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    long g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    long g4 = h4 + c - (1 << 26);

    // Select h if h < p, or h - p if h >= p
    long mask = g4 >> 63; // mask is either 0 (h >= p) or -1 (h < p)
    h0 &= mask;
    h1 &= mask;
    h2 &= mask;
    h3 &= mask;
    h4 &= mask;
    mask = ~mask;
    h0 |= g0 & mask;
    h1 |= g1 & mask;
    h2 |= g2 & mask;
    h3 |= g3 & mask;
    h4 |= g4 & mask;

    // h = h % (2^128)
    h0 = (h0 | (h1 << 26)) & 0xffffffffL;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffL;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffL;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffL;

    // mac = (h + pad) % (2^128)
    c = h0 + load32(key, 16);
    h0 = c & 0xffffffffL;
    c = h1 + load32(key, 20) + (c >> 32);
    h1 = c & 0xffffffffL;
    c = h2 + load32(key, 24) + (c >> 32);
    h2 = c & 0xffffffffL;
    c = h3 + load32(key, 28) + (c >> 32);
    h3 = c & 0xffffffffL;

    byte[] mac = new byte[MAC_TAG_SIZE_IN_BYTES];
    toByteArray(mac, h0, 0);
    toByteArray(mac, h1, 4);
    toByteArray(mac, h2, 8);
    toByteArray(mac, h3, 12);

    return mac;
  }

  static void verifyMac(final byte[] key, byte[] data, byte[] mac) throws GeneralSecurityException {
    if (!Bytes.equal(computeMac(key, data), mac)) {
      throw new GeneralSecurityException("invalid MAC");
    }
  }
}
