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
import java.util.Arrays;

/**
 * Defines X25519 function based on curve25519-donna C implementation (mostly identical).
 * See https://github.com/agl/curve25519-donna/blob/master/curve25519-donna.c
 *
 * Example Usage:
 *
 * Alice:
 * byte[] privateKeyA = Curve25519.GeneratePrivateKey();
 * byte[] publicKeyA = Curve25519.x25519PublicFromPrivate(privateKeyA);
 * Bob:
 * byte[] privateKeyB = Curve25519.GeneratePrivateKey();
 * byte[] publicKeyB = Curve25519.x25519PublicFromPrivate(privateKeyB);
 *
 * Alice sends publicKeyA to Bob and Bob sends publicKeyB to Alice.
 * Alice:
 * byte[] sharedSecretA = Curve25519.x25519(privateKeyA, publicKeyB);
 * Bob:
 * byte[] sharedSecretB = Curve25519.x25519(privateKeyB, publicKeyA);
 * such that sharedSecretA == sharedSecretB.
 */
@Alpha
public final class Curve25519 {
  /**
   * Computes Montgomery's double-and-add formulas.
   *
   * On entry and exit, the absolute value of the limbs of all inputs and outputs
   * are < 2^26.
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
      long[] x2, long[] z2, long[] x3, long[] z3, long[] x, long[] z, long[] xprime, long[] zprime,
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
    Field25519.sub(z, origx);  // does x - z
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
    Field25519.sub(zz, xx);  // does zz = xx - zz
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
   * if {@code iswap} is 0.  Runs in data-invariant time to avoid side-channel attacks.
   *
   * NOTE that this function requires that {@code iswap} be 1 or 0; other values give wrong results.
   * Also, the two limb arrays must be in reduced-coefficient, reduced-degree form: the values in
   * a[10..19] or b[10..19] aren't swapped, and all all values in a[0..9],b[0..9] must have
   * magnitude less than Integer.MAX_VALUE.
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
   * but leave {@code a} unchanged if 'iswap' is 0.  Runs in data-invariant time to avoid
   * side-channel attacks.
   *
   * NOTE that this function requires that {@code icopy} be 1 or 0; other values give wrong results.
   * Also, the two limb arrays must be in reduced-coefficient, reduced-degree form: the values in
   * a[10..19] or b[10..19] aren't swapped, and all all values in a[0..9],b[0..9] must have
   * magnitude less than Integer.MAX_VALUE.
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
   * @param resultx the x projective coordinate of the resulting curve point (short form)
   * @param resultz the z projective coordinate of the resulting curve point (short form)
   * @param n a little endian, 32-byte number
   * @param q a point of the curve (short form)
   */
  private static void curveMult(long[] resultx, long[] resultz, byte[] n, long[] q) {
    long[] nqpqx = new long[19];
    long[] nqpqz = new long[19]; nqpqz[0] = 1;
    long[] nqx = new long[19]; nqx[0] = 1;
    long[] nqz = new long[19];
    long[] nqpqx2 = new long[19];
    long[] nqpqz2 = new long[19]; nqpqz2[0] = 1;
    long[] nqx2 = new long[19];
    long[] nqz2 = new long[19]; nqz2[0] = 1;
    long[] t = null;

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

    System.arraycopy(nqx, 0, resultx, 0, Field25519.LIMB_CNT);
    System.arraycopy(nqz, 0, resultz, 0, Field25519.LIMB_CNT);
  }

  /**
   * Returns a 32-byte private key for Curve25519.
   *
   * Note from BoringSSL: All X25519 implementations should decode scalars correctly (see
   * https://tools.ietf.org/html/rfc7748#section-5). However, if an implementation doesn't then it
   * might interoperate with random keys a fraction of the time because they'll, randomly, happen to
   * be correctly formed.
   *
   * Thus we do the opposite of the masking here to make sure that our private keys are never
   * correctly masked and so, hopefully, any incorrect implementations are deterministically broken.
   *
   * This does not affect security because, although we're throwing away entropy, a valid
   * implementation of x25519 should throw away the exact same bits anyway.
   */
  @SuppressWarnings("NarrowingCompoundAssignment")
  public static byte[] generatePrivateKey() {
    byte[] privateKey = Random.randBytes(Field25519.FIELD_LEN);

    privateKey[0] |= 7;
    privateKey[31] &= 63;
    privateKey[31] |= 128;

    return privateKey;
  }

  /**
   * Returns the 32-byte shared key (i.e., privateKey·peersPublicValue on the curve).
   *
   * @param privateKey 32-byte private key
   * @param peersPublicValue 32-byte public value
   * @return the 32-byte shared key
   * @throws IllegalArgumentException when either {@code privateKey} or {@code peersPublicValue} is
   * not 32 bytes.
   */
  @SuppressWarnings("NarrowingCompoundAssignment")
  public static byte[] x25519(byte[] privateKey, byte[] peersPublicValue) {
    if (privateKey.length != Field25519.FIELD_LEN) {
      throw new IllegalArgumentException("Private key must have 32 bytes.");
    }
    if (peersPublicValue.length != Field25519.FIELD_LEN) {
      throw new IllegalArgumentException("Peer's public key must have 32 bytes.");
    }
    long[] x = new long[Field25519.LIMB_CNT];
    long[] z = new long[Field25519.LIMB_CNT + 1];
    long[] zmone = new long[Field25519.LIMB_CNT];

    byte[] e = Arrays.copyOf(privateKey, Field25519.FIELD_LEN);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    long[] bp = Field25519.expand(peersPublicValue);
    curveMult(x, z, e, bp);
    Field25519.inverse(zmone, z);
    Field25519.mult(z, x, zmone);
    return Field25519.contract(z);
  }

  /**
   * Returns the 32-byte Diffie-Hellman public value based on the given  {@code privateKey} (i.e.,
   * {@code privateKey}·[9] on the curve).
   *
   * @param privateKey 32-byte private key
   * @return 32-byte Diffie-Hellman public value
   * @throws IllegalArgumentException when the {@code privateKey} is not 32 bytes.
   */
  public static byte[] x25519PublicFromPrivate(byte[] privateKey) {
    if (privateKey.length != Field25519.FIELD_LEN) {
      throw new IllegalArgumentException("Private key must have 32 bytes.");
    }
    byte[] base = new byte[Field25519.FIELD_LEN]; base[0] = 9;
    return x25519(privateKey, base);
  }
}
