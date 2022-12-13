// Copyright 2022 Google LLC
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

package com.google.crypto.tink.internal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Helper class with functions that encode and decode non-negative {@link java.math.BigInteger} to
 * and from {@code byte[]}.
 */
public final class BigIntegerEncoding {

  /**
   * Encodes a non-negative {@link java.math.BigInteger} into the minimal two's-complement
   * representation in big-endian byte-order.
   *
   * <p>The most significant bit of the first byte is the sign bit, which is always 0 because the
   * input number is non-negative. Because of that, the output is at the same time also an unsigned
   * big-endian encoding that may have an additional zero byte at the beginning, and can be parsed
   * with {@link #fromUnsignedBigEndianBytes}.
   */
  public static byte[] toBigEndianBytes(BigInteger n) {
    if (n.signum() == -1) {
      throw new IllegalArgumentException("n must not be negative");
    }
    return n.toByteArray();
  }

  /**
   * Encodes a non-negative {@link java.math.BigInteger} into a byte array of a specified length,
   * using big-endian byte-order.
   *
   * <p>See also <a href="https://www.rfc-editor.org/rfc/rfc8017#section-4.2">RFC 8017, Sec. 4.2</a>
   *
   * <p>throws a GeneralSecurityException if the number is negative or length is too short.
   */
  public static byte[] toBigEndianBytesOfFixedLength(BigInteger n, int length)
      throws GeneralSecurityException {
    if (n.signum() == -1) {
      throw new IllegalArgumentException("integer must be nonnegative");
    }
    byte[] b = n.toByteArray();
    if (b.length == length) {
      return b;
    }
    if (b.length > length + 1 /* potential leading zero */) {
      throw new GeneralSecurityException("integer too large");
    }
    if (b.length == length + 1) {
      if (b[0] == 0 /* leading zero */) {
        return Arrays.copyOfRange(b, 1, b.length);
      } else {
        throw new GeneralSecurityException("integer too large");
      }
    }
    // Left zero pad b.
    byte[] res = new byte[length];
    System.arraycopy(b, 0, res, length - b.length, b.length);
    return res;
  }

  /**
   * Parses a {@link BigInteger} from a byte array using unsigned big-endian encoding.
   *
   * <p>See also <a href="https://www.rfc-editor.org/rfc/rfc8017#section-4.2">RFC 8017, Sec. 4.2</a>
   */
  public static BigInteger fromUnsignedBigEndianBytes(byte[] bytes) {
    return new BigInteger(1, bytes);
  }

  private BigIntegerEncoding() {}
}
