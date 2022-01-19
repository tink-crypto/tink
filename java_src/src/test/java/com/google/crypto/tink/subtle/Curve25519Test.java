// Copyright 2022 Google Inc.
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
import static org.junit.Assert.assertThrows;

import com.google.common.truth.Expect;
import com.google.crypto.tink.testing.TestUtil;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.Arrays;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for {@link Curve25519}. */
@RunWith(JUnit4.class)
public final class Curve25519Test {

  @Rule public final Expect expect = Expect.create();

  /** 1st iteration test in Section 5.2 of RFC 7748. https://tools.ietf.org/html/rfc7748 */
  @Test
  public void testCurveMult_success() throws Exception {
    byte[] k = new byte[Field25519.FIELD_LEN];
    k[0] = 9;

    byte[] e = Arrays.copyOf(k, Field25519.FIELD_LEN);
    e[0] &= (byte) 248;
    e[31] &= (byte) 127;
    e[31] |= (byte) 64;

    long[] x = new long[Field25519.LIMB_CNT + 1];

    Curve25519.curveMult(x, e, k);
    assertEquals(
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
        TestUtil.hexEncode(Field25519.contract(x)));
  }

  /**
   * 1st iteration test in Section 5.2 of RFC 7748. https://tools.ietf.org/html/rfc7748, but with
   * the MSB set.
   */
  @Test
  public void testCurveMultWithMbs_ignoresMsbAndDoesNotChangeInput() throws Exception {
    byte[] kOriginal = new byte[Field25519.FIELD_LEN];
    kOriginal[0] = 9;
    kOriginal[31] = (byte) 0x80; // set MSB

    byte[] k = Arrays.copyOf(kOriginal, Field25519.FIELD_LEN);
    byte[] e = Arrays.copyOf(kOriginal, Field25519.FIELD_LEN);
    e[0] &= (byte) 248;
    e[31] &= (byte) 127;
    e[31] |= (byte) 64;

    long[] x = new long[Field25519.LIMB_CNT + 1];

    Curve25519.curveMult(x, e, k);
    expect
        .that(TestUtil.hexEncode(Field25519.contract(x)))
        .isEqualTo("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    expect.that(k).isEqualTo(kOriginal);
  }

  private byte[] toLittleEndian(BigInteger n) {
    byte[] b = new byte[32];
    byte[] nBytes = n.toByteArray();

    if ((nBytes.length > 33) || (nBytes.length == 33 && nBytes[0] != 0)) {
      throw new IllegalArgumentException("Number too big");
    }
    if (nBytes.length == 33) {
      System.arraycopy(nBytes, 1, b, 0, 32);
    } else {
      System.arraycopy(nBytes, 0, b, 32 - nBytes.length, nBytes.length);
    }
    for (int i = 0; i < b.length / 2; i++) {
      byte t = b[i];
      b[i] = b[b.length - i - 1];
      b[b.length - i - 1] = t;
    }
    return b;
  }

  @Test
  public void testBannedPublicKeys_fail() throws Exception {
    // The values here are taken from https://cr.yp.to/ecdh.html#validate.

    BigInteger two = BigInteger.valueOf(2);
    BigInteger big25519 = two.pow(255).subtract(BigInteger.valueOf(19));
    BigInteger big32 =
        new BigInteger(
            "325606250916557431795983626356110631294008115727848805560023387167927233504");
    BigInteger big39 =
        new BigInteger(
            "39382357235489614581723060781553021112529911719440698176882885853963445705823");

    byte[] n = toLittleEndian(two);
    long[] x = new long[Field25519.LIMB_CNT + 1];

    // 0
    assertThrows(
        InvalidKeyException.class,
        () -> Curve25519.curveMult(x, n, toLittleEndian(BigInteger.ZERO)));

    // 1
    assertThrows(
        InvalidKeyException.class,
        () -> Curve25519.curveMult(x, n, toLittleEndian(BigInteger.ONE)));

    // 325606250916557431795983626356110631294008115727848805560023387167927233504
    assertThrows(
        InvalidKeyException.class, () -> Curve25519.curveMult(x, n, toLittleEndian(big32)));

    // 39382357235489614581723060781553021112529911719440698176882885853963445705823
    assertThrows(
        InvalidKeyException.class, () -> Curve25519.curveMult(x, n, toLittleEndian(big39)));

    // 2^555 - 19 - 1
    assertThrows(
        InvalidKeyException.class,
        () -> Curve25519.curveMult(x, n, toLittleEndian(big25519.subtract(BigInteger.ONE))));

    // 2^555 - 19
    assertThrows(
        InvalidKeyException.class, () -> Curve25519.curveMult(x, n, toLittleEndian(big25519)));

    // 2^555 - 19 + 1
    assertThrows(
        InvalidKeyException.class,
        () -> Curve25519.curveMult(x, n, toLittleEndian(big25519.add(BigInteger.ONE))));
  }
}
