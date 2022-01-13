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

import com.google.crypto.tink.annotations.Alpha;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * This class implements point arithmetic on the elliptic curve <a
 * href="https://cr.yp.to/ecdh/curve25519-20060209.pdf">Curve25519</a>.
 *
 * <p>This class only implements point arithmetic, if you want to use the ECDH Curve25519 function,
 * please checkout {@link com.google.crypto.tink.subtle.X25519}.
 *
 * <p>This implementation is based on <a
 * href="https://github.com/agl/curve25519-donna/blob/master/curve25519-donna.c">curve255-donna C
 * implementation</a>.
 */
@Alpha
final class Curve25519 {
  // https://cr.yp.to/ecdh.html#validate doesn't recommend validating peer's public key. However,
  // validating public key doesn't harm security and in certain cases, prevents unwanted edge
  // cases.
  // As we clear the most significant bit of peer's public key, we don't have to include public keys
  // that are larger than 2^255.
  static final byte[][] BANNED_PUBLIC_KEYS =
      new byte[][] {
        // 0
        new byte[] {
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        },
        // 1
        new byte[] {
          (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
          (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        },
        // 325606250916557431795983626356110631294008115727848805560023387167927233504
        new byte[] {
          (byte) 0xe0, (byte) 0xeb, (byte) 0x7a, (byte) 0x7c,
          (byte) 0x3b, (byte) 0x41, (byte) 0xb8, (byte) 0xae,
          (byte) 0x16, (byte) 0x56, (byte) 0xe3, (byte) 0xfa,
          (byte) 0xf1, (byte) 0x9f, (byte) 0xc4, (byte) 0x6a,
          (byte) 0xda, (byte) 0x09, (byte) 0x8d, (byte) 0xeb,
          (byte) 0x9c, (byte) 0x32, (byte) 0xb1, (byte) 0xfd,
          (byte) 0x86, (byte) 0x62, (byte) 0x05, (byte) 0x16,
          (byte) 0x5f, (byte) 0x49, (byte) 0xb8, (byte) 0x00,
        },
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823
        new byte[] {
          (byte) 0x5f, (byte) 0x9c, (byte) 0x95, (byte) 0xbc,
          (byte) 0xa3, (byte) 0x50, (byte) 0x8c, (byte) 0x24,
          (byte) 0xb1, (byte) 0xd0, (byte) 0xb1, (byte) 0x55,
          (byte) 0x9c, (byte) 0x83, (byte) 0xef, (byte) 0x5b,
          (byte) 0x04, (byte) 0x44, (byte) 0x5c, (byte) 0xc4,
          (byte) 0x58, (byte) 0x1c, (byte) 0x8e, (byte) 0x86,
          (byte) 0xd8, (byte) 0x22, (byte) 0x4e, (byte) 0xdd,
          (byte) 0xd0, (byte) 0x9f, (byte) 0x11, (byte) 0x57
        },
        // 2^255 - 19 - 1
        new byte[] {
          (byte) 0xec, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f,
        },
        // 2^255 - 19
        new byte[] {
          (byte) 0xed, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f
        },
        // 2^255 - 19 + 1
        new byte[] {
          (byte) 0xee, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x7f
        }
      };
  /**
   * Computes Montgomery's double-and-add formulas.
   *
   * <p>On entry and exit, the absolute value of the limbs of all inputs and outputs are < 2^26.
   *
   * @param x2 x projective coordinate of output 2Q, long form
   * @param z2 z projective coordinate of output 2Q, long form
   * @param x3 x projective coordinate of output Q + Q', long form
   * @param z3 z projective coordinate of output Q + Q', long form
   * @param x x projective coordinate of input Q, short form, destroyed
   * @param z z projective coordinate of input Q, short form, destroyed
   * @param xprime x projective coordinate of input Q', short form, destroyed
   * @param zprime z projective coordinate of input Q', short form, destroyed
   * @param qmqp input Q - Q', short form, preserved
   */
  private static void monty(
      long[] x2,
      long[] z2,
      long[] x3,
      long[] z3,
      long[] x,
      long[] z,
      long[] xprime,
      long[] zprime,
      long[] qmqp) {
    long[] origx = Arrays.copyOf(x, Field25519.LIMB_CNT);
    long[] zzz = new long[19];
    long[] xx = new long[19];
    long[] zz = new long[19];
    long[] xxprime = new long[19];
    long[] zzprime = new long[19];
    long[] zzzprime = new long[19];
    long[] xxxprime = new long[19];

    Field25519.sum(x, z);
    // |x[i]| < 2^27
    Field25519.sub(z, origx); // does x - z
    // |z[i]| < 2^27

    long[] origxprime = Arrays.copyOf(xprime, Field25519.LIMB_CNT);
    Field25519.sum(xprime, zprime);
    // |xprime[i]| < 2^27
    Field25519.sub(zprime, origxprime);
    // |zprime[i]| < 2^27
    Field25519.product(xxprime, xprime, z);
    // |xxprime[i]| < 14*2^54: the largest product of two limbs will be < 2^(27+27) and {@ref
    // Field25519#product} adds together, at most, 14 of those products. (Approximating that to
    // 2^58 doesn't work out.)
    Field25519.product(zzprime, x, zprime);
    // |zzprime[i]| < 14*2^54
    Field25519.reduceSizeByModularReduction(xxprime);
    Field25519.reduceCoefficients(xxprime);
    // |xxprime[i]| < 2^26
    Field25519.reduceSizeByModularReduction(zzprime);
    Field25519.reduceCoefficients(zzprime);
    // |zzprime[i]| < 2^26
    System.arraycopy(xxprime, 0, origxprime, 0, Field25519.LIMB_CNT);
    Field25519.sum(xxprime, zzprime);
    // |xxprime[i]| < 2^27
    Field25519.sub(zzprime, origxprime);
    // |zzprime[i]| < 2^27
    Field25519.square(xxxprime, xxprime);
    // |xxxprime[i]| < 2^26
    Field25519.square(zzzprime, zzprime);
    // |zzzprime[i]| < 2^26
    Field25519.product(zzprime, zzzprime, qmqp);
    // |zzprime[i]| < 14*2^52
    Field25519.reduceSizeByModularReduction(zzprime);
    Field25519.reduceCoefficients(zzprime);
    // |zzprime[i]| < 2^26
    System.arraycopy(xxxprime, 0, x3, 0, Field25519.LIMB_CNT);
    System.arraycopy(zzprime, 0, z3, 0, Field25519.LIMB_CNT);

    Field25519.square(xx, x);
    // |xx[i]| < 2^26
    Field25519.square(zz, z);
    // |zz[i]| < 2^26
    Field25519.product(x2, xx, zz);
    // |x2[i]| < 14*2^52
    Field25519.reduceSizeByModularReduction(x2);
    Field25519.reduceCoefficients(x2);
    // |x2[i]| < 2^26
    Field25519.sub(zz, xx); // does zz = xx - zz
    // |zz[i]| < 2^27
    Arrays.fill(zzz, Field25519.LIMB_CNT, zzz.length - 1, 0);
    Field25519.scalarProduct(zzz, zz, 121665);
    // |zzz[i]| < 2^(27+17)
    // No need to call reduceSizeByModularReduction here: scalarProduct doesn't increase the degree
    // of its input.
    Field25519.reduceCoefficients(zzz);
    // |zzz[i]| < 2^26
    Field25519.sum(zzz, xx);
    // |zzz[i]| < 2^27
    Field25519.product(z2, zz, zzz);
    // |z2[i]| < 14*2^(26+27)
    Field25519.reduceSizeByModularReduction(z2);
    Field25519.reduceCoefficients(z2);
    // |z2|i| < 2^26
  }

  /**
   * Conditionally swap two reduced-form limb arrays if {@code iswap} is 1, but leave them unchanged
   * if {@code iswap} is 0. Runs in data-invariant time to avoid side-channel attacks.
   *
   * <p>NOTE that this function requires that {@code iswap} be 1 or 0; other values give wrong
   * results. Also, the two limb arrays must be in reduced-coefficient, reduced-degree form: the
   * values in a[10..19] or b[10..19] aren't swapped, and all all values in a[0..9],b[0..9] must
   * have magnitude less than Integer.MAX_VALUE.
   */
  static void swapConditional(long[] a, long[] b, int iswap) {
    int swap = -iswap;
    for (int i = 0; i < Field25519.LIMB_CNT; i++) {
      int x = swap & (((int) a[i]) ^ ((int) b[i]));
      a[i] = ((int) a[i]) ^ x;
      b[i] = ((int) b[i]) ^ x;
    }
  }

  /**
   * Conditionally copies a reduced-form limb arrays {@code b} into {@code a} if {@code icopy} is 1,
   * but leave {@code a} unchanged if 'iswap' is 0. Runs in data-invariant time to avoid
   * side-channel attacks.
   *
   * <p>NOTE that this function requires that {@code icopy} be 1 or 0; other values give wrong
   * results. Also, the two limb arrays must be in reduced-coefficient, reduced-degree form: the
   * values in a[10..19] or b[10..19] aren't swapped, and all all values in a[0..9],b[0..9] must
   * have magnitude less than Integer.MAX_VALUE.
   */
  static void copyConditional(long[] a, long[] b, int icopy) {
    int copy = -icopy;
    for (int i = 0; i < Field25519.LIMB_CNT; i++) {
      int x = copy & (((int) a[i]) ^ ((int) b[i]));
      a[i] = ((int) a[i]) ^ x;
    }
  }

  /**
   * Calculates nQ where Q is the x-coordinate of a point on the curve.
   *
   * @param resultx the x projective coordinate of the resulting curve point (short form).
   * @param n a little endian, 32-byte number.
   * @param qBytes a little endian, 32-byte number representing the public point' x coordinate.
   * @throws InvalidKeyException iff the public key is in the banned list or its length is not
   *     32-byte.
   * @throws IllegalStateException iff there is arithmetic error.
   */
  static void curveMult(long[] resultx, byte[] n, byte[] qBytes) throws InvalidKeyException {
    byte[] qBytesWithoutMsb = validatePubKeyAndClearMsb(qBytes);

    long[] q = Field25519.expand(qBytesWithoutMsb);
    long[] nqpqx = new long[19];
    long[] nqpqz = new long[19];
    nqpqz[0] = 1;
    long[] nqx = new long[19];
    nqx[0] = 1;
    long[] nqz = new long[19];
    long[] nqpqx2 = new long[19];
    long[] nqpqz2 = new long[19];
    nqpqz2[0] = 1;
    long[] nqx2 = new long[19];
    long[] nqz2 = new long[19];
    nqz2[0] = 1;
    long[] t = new long[19];

    System.arraycopy(q, 0, nqpqx, 0, Field25519.LIMB_CNT);

    for (int i = 0; i < Field25519.FIELD_LEN; i++) {
      int b = n[Field25519.FIELD_LEN - i - 1] & 0xff;
      for (int j = 0; j < 8; j++) {
        int bit = (b >> (7 - j)) & 1;

        swapConditional(nqx, nqpqx, bit);
        swapConditional(nqz, nqpqz, bit);
        monty(nqx2, nqz2, nqpqx2, nqpqz2, nqx, nqz, nqpqx, nqpqz, q);
        swapConditional(nqx2, nqpqx2, bit);
        swapConditional(nqz2, nqpqz2, bit);

        t = nqx;
        nqx = nqx2;
        nqx2 = t;
        t = nqz;
        nqz = nqz2;
        nqz2 = t;
        t = nqpqx;
        nqpqx = nqpqx2;
        nqpqx2 = t;
        t = nqpqz;
        nqpqz = nqpqz2;
        nqpqz2 = t;
      }
    }

    // Computes nqx/nqz.
    long[] zmone = new long[Field25519.LIMB_CNT];
    Field25519.inverse(zmone, nqz);
    Field25519.mult(resultx, nqx, zmone);

    // Nowadays it should be standard to protect public key crypto against flaws. I.e. if there is a
    // computation error through a faulty CPU or if the implementation contains a bug, then if
    // possible this should be detected at run time.
    //
    // The situation is a bit more tricky for X25519 where for example the implementation
    // proposed in https://tools.ietf.org/html/rfc7748 only uses the x-coordinate. However, a
    // verification is still possible, but depends on the actual computation.
    //
    // Tink's Java implementation is equivalent to RFC7748. We will use the loop invariant in the
    // Montgomery ladder to detect fault computation. In particular, we use the following invariant:
    // q, resultx, nqpqx/nqpqx  are x coordinates of 3 collinear points q, n*q, (n + 1)*q.
    if (!isCollinear(q, resultx, nqpqx, nqpqz)) {
      throw new IllegalStateException(
          "Arithmetic error in curve multiplication with the public key: "
              + Hex.encode(qBytes));
    }
  }

  /**
   * Validates public key and clear its most significant bit.
   *
   * @throws InvalidKeyException iff the {@code pubKey} is in the banned list or its length is not
   *     32-byte.
   */
  private static byte[] validatePubKeyAndClearMsb(byte[] pubKey) throws InvalidKeyException {
    if (pubKey.length != 32) {
      throw new InvalidKeyException("Public key length is not 32-byte");
    }
    // Clears the most significant bit as in the method decodeUCoordinate() of RFC7748.
    byte[] pubKeyWithoutMsb = Arrays.copyOf(pubKey, pubKey.length);
    pubKeyWithoutMsb[31] &= (byte) 0x7f;

    for (int i = 0; i < BANNED_PUBLIC_KEYS.length; i++) {
      if (Bytes.equal(BANNED_PUBLIC_KEYS[i], pubKeyWithoutMsb)) {
        throw new InvalidKeyException("Banned public key: " + Hex.encode(BANNED_PUBLIC_KEYS[i]));
      }
    }
    return pubKeyWithoutMsb;
  }

  /**
   * Checks whether there are three collinear points with x coordinate x1, x2, x3/z3.
   *
   * @return true if three collinear points with x coordianate x1, x2, x3/z3 are collinear.
   */
  private static boolean isCollinear(long[] x1, long[] x2, long[] x3, long[] z3) {
    // If x1, x2, x3 (in this method x3 is represented as x3/z3) are the x-coordinates of three
    // collinear points on a curve, then they satisfy the equation
    //   y^2 = x^3 + ax^2 + x
    // They also satisfy the equation
    //   0 = (x - x1)(x - x2)(x - x3)
    //     = x^3 + Ax^2 + Bx + C
    // where
    //   A = - x1 - x2 - x3
    //   B = x1*x2 + x2*x3 + x3*x1
    //   C = - x1*x2*x3
    // Hence, the three points also satisfy
    //   y^2 = (a - A)x^2 + (1 - B)x - C
    // This is a quadratic curve. Three distinct collinear points can only be on a quadratic
    // curve if the quadratic curve has a line as component. And if a quadratic curve has a line
    // as component then its discriminant is 0.
    // Therefore, discriminant((a - A)x^2 + (1-B)x - C) = 0.
    // In particular:
    //   a = 486662
    //   lhs = 4 * ((x1 + x2 + a) * z3 + x3) * (x1 * x2 * x3)
    //   rhs = ((x1 * x2 - 1) * z3 + x3 * (x1 + x2))**2
    //   assert (lhs - rhs)  == 0
    //
    // There are 2 cases that we haven't discussed:
    //
    //   * If x1 and x2 are both points with y-coordinate 0 then the argument doesn't hold.
    //   However, our ECDH computation doesn't allow points of low order (see {@code
    //   validatePublicKey}). Therefore, this edge case never happen.
    //
    //   * x1, x2 or x3/y3 may be points on the twist. If so, they satisfy the equation
    //     2y^2 = x^3 + ax^2 + x
    //   Hence, the three points also satisfy
    //     2y^2 = (a - A)x^2 + (1 - B)x - C
    //   Thus, this collinear check should work for this case too.
    long[] x1multx2 = new long[Field25519.LIMB_CNT];
    long[] x1addx2 = new long[Field25519.LIMB_CNT];
    long[] lhs = new long[Field25519.LIMB_CNT + 1];
    long[] t = new long[Field25519.LIMB_CNT + 1];
    long[] t2 = new long[Field25519.LIMB_CNT + 1];
    Field25519.mult(x1multx2, x1, x2);
    Field25519.sum(x1addx2, x1, x2);
    long[] a = new long[Field25519.LIMB_CNT];
    a[0] = 486662;
    // t = x1 + x2 + a
    Field25519.sum(t, x1addx2, a);
    // t = (x1 + x2 + a) * z3
    Field25519.mult(t, t, z3);
    // t = (x1 + x2 + a) * z3 + x3
    Field25519.sum(t, x3);
    // t = ((x1 + x2 + a) * z3 + x3) * x1 * x2
    Field25519.mult(t, t, x1multx2);
    // t = ((x1 + x2 + a) * z3 + x3) * (x1 * x2 * x3)
    Field25519.mult(t, t, x3);
    Field25519.scalarProduct(lhs, t, 4);
    Field25519.reduceCoefficients(lhs);

    // t = x1 * x2 * z3
    Field25519.mult(t, x1multx2, z3);
    // t = x1 * x2 * z3 - z3
    Field25519.sub(t, t, z3);
    // t2 = (x1 + x2) * x3
    Field25519.mult(t2, x1addx2, x3);
    // t = x1 * x2 * z3 - z3 + (x1 + x2) * x3
    Field25519.sum(t, t, t2);
    // t = (x1 * x2 * z3 - z3 + (x1 + x2) * x3)^2
    Field25519.square(t, t);
    return Bytes.equal(Field25519.contract(lhs), Field25519.contract(t));
  }

  private Curve25519() {}
}
