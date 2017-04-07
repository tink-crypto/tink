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

package com.google.cloud.crypto.tink.subtle;

import static com.google.common.base.Preconditions.checkArgument;

import java.util.Arrays;

/**
 * Defines X25519 function based on curve25519-donna C implementation (mostly identical).
 * See https://github.com/agl/curve25519-donna/blob/master/curve25519-donna.c
 *
 * Field element representation:
 *
 * Field elements are written as an array of signed, 64-bit limbs (an array of longs), least
 * significant first. The value of the field element is:
 *   x[0] + 2^26·x[1] + x^51·x[2] + 2^77·x[3] + 2^102·x[4] + 2^128·x[5] + x^153·x[6] + 2^179·x[7]
 *   + 2^204·x[8] + 2^230·x[9]
 *
 * i.e. the limbs are 26, 25, 26, 25, ... bits wide.
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
public final class Curve25519 {

  private static final int BYTE_LEN = 32;
  private static final int LIMB_CNT = 10;
  private static final long TWO_TO_25 = 1 << 25;
  private static final long TWO_TO_26 = TWO_TO_25 << 1;

  private static final int[] EXPAND_START = {0, 3, 6, 9, 12, 16, 19, 22, 25, 28};
  private static final int[] EXPAND_SHIFT = {0, 2, 3, 5, 6, 0, 1, 3, 4, 6};
  private static final int[] MASK = {0x3ffffff, 0x1ffffff};
  private static final int[] SHIFT = {26, 25};

  /**
   * Sums two numbers: output += in
   */
  private static void sum(long[] output, long[] in) {
    for (int i = 0; i < LIMB_CNT; i++) {
      output[i] += in[i];
    }
  }

  /**
   * Find the difference of two numbers: output = in - output
   * (note the order of the arguments!).
  */
  private static void sub(long[] output, long[] in) {
    for (int i = 0; i < LIMB_CNT; i++) {
      output[i] = in[i] - output[i];
    }
  }

  /**
   * Multiply a number by a scalar: output = in * scalar
   */
  private static void scalarProduct(long[] output, long[] in, long scalar) {
    for (int i = 0; i < LIMB_CNT; i++) {
      output[i] = in[i] * scalar;
    }
  }

  /**
   * Multiply two numbers: out = in2 * in
   *
   * output must be distinct to both inputs. The inputs are reduced coefficient form,
   * the output is not.
   *
   * out[x] <= 14 * the largest product of the input limbs.
   */
  private static void product(long[] out, long[] in2, long[] in) {
    out[0] = in2[0] * in[0];
    out[1] = in2[0] * in[1]
        + in2[1] * in[0];
    out[2] = 2 * in2[1] * in[1]
        + in2[0] * in[2]
        + in2[2] * in[0];
    out[3] = in2[1] * in[2]
        + in2[2] * in[1]
        + in2[0] * in[3]
        + in2[3] * in[0];
    out[4] = in2[2] * in[2]
        + 2 * (in2[1] * in[3] + in2[3] * in[1])
        + in2[0] * in[4]
        + in2[4] * in[0];
    out[5] = in2[2] * in[3]
        + in2[3] * in[2]
        + in2[1] * in[4]
        + in2[4] * in[1]
        + in2[0] * in[5]
        + in2[5] * in[0];
    out[6] = 2 * (in2[3] * in[3] + in2[1] * in[5] + in2[5] * in[1])
        + in2[2] * in[4]
        + in2[4] * in[2]
        + in2[0] * in[6]
        + in2[6] * in[0];
    out[7] = in2[3] * in[4]
        + in2[4] * in[3]
        + in2[2] * in[5]
        + in2[5] * in[2]
        + in2[1] * in[6]
        + in2[6] * in[1]
        + in2[0] * in[7]
        + in2[7] * in[0];
    out[8] = in2[4] * in[4]
        + 2 * (in2[3] * in[5] + in2[5] * in[3] + in2[1] * in[7] + in2[7] * in[1])
        + in2[2] * in[6]
        + in2[6] * in[2]
        + in2[0] * in[8]
        + in2[8] * in[0];
    out[9] = in2[4] * in[5]
        + in2[5] * in[4]
        + in2[3] * in[6]
        + in2[6] * in[3]
        + in2[2] * in[7]
        + in2[7] * in[2]
        + in2[1] * in[8]
        + in2[8] * in[1]
        + in2[0] * in[9]
        + in2[9] * in[0];
    out[10] =
        2 * (in2[5] * in[5] + in2[3] * in[7] + in2[7] * in[3] + in2[1] * in[9] + in2[9] * in[1])
            + in2[4] * in[6]
            + in2[6] * in[4]
            + in2[2] * in[8]
            + in2[8] * in[2];
    out[11] = in2[5] * in[6]
        + in2[6] * in[5]
        + in2[4] * in[7]
        + in2[7] * in[4]
        + in2[3] * in[8]
        + in2[8] * in[3]
        + in2[2] * in[9]
        + in2[9] * in[2];
    out[12] = in2[6] * in[6]
        + 2 * (in2[5] * in[7] + in2[7] * in[5] + in2[3] * in[9] + in2[9] * in[3])
        + in2[4] * in[8]
        + in2[8] * in[4];
    out[13] = in2[6] * in[7]
        + in2[7] * in[6]
        + in2[5] * in[8]
        + in2[8] * in[5]
        + in2[4] * in[9]
        + in2[9] * in[4];
    out[14] = 2 * (in2[7] * in[7] + in2[5] * in[9] + in2[9] * in[5])
        + in2[6] * in[8]
        + in2[8] * in[6];
    out[15] = in2[7] * in[8]
        + in2[8] * in[7]
        + in2[6] * in[9]
        + in2[9] * in[6];
    out[16] = in2[8] * in[8]
        + 2 * (in2[7] * in[9] + in2[9] * in[7]);
    out[17] = in2[8] * in[9]
        + in2[9] * in[8];
    out[18] = 2 * in2[9] * in[9];
  }

  /**
   * Reduce a long form to a short form by taking the input mod 2^255 - 19.
   *
   * On entry: |output[i]| < 14*2^54
   * On exit: |output[0..8]| < 280*2^54
   */
  private static void reduceDegree(long[] output) {
    // Each of these shifts and adds ends up multiplying the value by 19.
    //
    // For output[0..8], the absolute entry value is < 14*2^54 and we add, at most, 19*14*2^54 thus,
    // on exit, |output[0..8]| < 280*2^54.
    output[8] += output[18] << 4;
    output[8] += output[18] << 1;
    output[8] += output[18];
    output[7] += output[17] << 4;
    output[7] += output[17] << 1;
    output[7] += output[17];
    output[6] += output[16] << 4;
    output[6] += output[16] << 1;
    output[6] += output[16];
    output[5] += output[15] << 4;
    output[5] += output[15] << 1;
    output[5] += output[15];
    output[4] += output[14] << 4;
    output[4] += output[14] << 1;
    output[4] += output[14];
    output[3] += output[13] << 4;
    output[3] += output[13] << 1;
    output[3] += output[13];
    output[2] += output[12] << 4;
    output[2] += output[12] << 1;
    output[2] += output[12];
    output[1] += output[11] << 4;
    output[1] += output[11] << 1;
    output[1] += output[11];
    output[0] += output[10] << 4;
    output[0] += output[10] << 1;
    output[0] += output[10];
  }

  /**
   * Reduce all coefficients of the short form input so that |x| < 2^26.
   *
   * On entry: |output[i]| < 280*2^54
   */
  private static void reduceCoefficients(long[] output) {
    output[10] = 0;

    for (int i = 0; i < LIMB_CNT; i += 2) {
      long over = output[i] / TWO_TO_26;
      // The entry condition (that |output[i]| < 280*2^54) means that over is, at most, 280*2^28 in
      // the first iteration of this loop. This is added to the next limb and we can approximate the
      // resulting bound of that limb by 281*2^54.
      output[i] -= over << 26;
      output[i + 1] += over;

      // For the first iteration, |output[i+1]| < 281*2^54, thus |over| < 281*2^29. When this is
      // added to the next limb, the resulting bound can be approximated as 281*2^54.
      //
      // For subsequent iterations of the loop, 281*2^54 remains a conservative bound and no
      // overflow occurs.
      over = output[i + 1] / TWO_TO_25;
      output[i + 1] -= over << 25;
      output[i + 2] += over;
    }
    // Now |output[10]| < 281*2^29 and all other coefficients are reduced.
    output[0] += output[10] << 4;
    output[0] += output[10] << 1;
    output[0] += output[10];

    output[10] = 0;
    // Now output[1..9] are reduced, and |output[0]| < 2^26 + 19*281*2^29 so |over| will be no more
    // than 2^16.
    long over = output[0] / TWO_TO_26;
    output[0] -= over << 26;
    output[1] += over;
    // Now output[0,2..9] are reduced, and |output[1]| < 2^25 + 2^16 < 2^26. The bound on
    // |output[1]| is sufficient to meet our needs.
  }

  /**
   * A helpful wrapper around fproduct: output = in * in2.
   *
   * On entry: |in[i]| < 2^27 and |in2[i]| < 2^27.
   *
   * The output is reduced degree (indeed, one need only provide storage for 10 limbs) and
   * |output[i]| < 2^26.
   */
  private static void mult(long[] output, long[] in, long[] in2) {
    long[] t = new long[19];
    product(t, in, in2);
    // |t[i]| < 14*2^54
    reduceDegree(t);
    reduceCoefficients(t);
    // |t[i]| < 2^26
    System.arraycopy(t, 0, output, 0, LIMB_CNT);
  }

  /**
   * Square a number: out = in**2
   *
   * output must be distinct from the input. The inputs are reduced coefficient form, the output is
   * not.
   *
   * out[x] <= 14 * the largest product of the input limbs.
   */
  private static void squareInner(long[] out, long[] in) {
    out[0] = in[0] * in[0];
    out[1] =  2 * in[0] * in[1];
    out[2] =  2 * (in[1] * in[1] + in[0] * in[2]);
    out[3] =  2 * (in[1] * in[2] + in[0] * in[3]);
    out[4] = in[2] * in[2]
        + 4 * in[1] * in[3]
        + 2 * in[0] * in[4];
    out[5] =  2 * (in[2] * in[3] + in[1] * in[4] + in[0] * in[5]);
    out[6] =  2 * (in[3] * in[3] + in[2] * in[4] + in[0] * in[6] + 2 *  in[1] * in[5]);
    out[7] =  2 * (in[3] * in[4] + in[2] * in[5] + in[1] * in[6] + in[0] * in[7]);
    out[8] = in[4] * in[4]
        + 2 * (in[2] * in[6] + in[0] * in[8] + 2 * (in[1] * in[7] + in[3] * in[5]));
    out[9] =  2 * (in[4] * in[5] + in[3] * in[6] + in[2] * in[7] + in[1] * in[8] + in[0] * in[9]);
    out[10] = 2 * (in[5] * in[5]
        + in[4] * in[6]
        + in[2] * in[8]
        + 2 * (in[3] * in[7] + in[1] * in[9]));
    out[11] = 2 * (in[5] * in[6] + in[4] * in[7] + in[3] * in[8] + in[2] * in[9]);
    out[12] = in[6] * in[6]
        + 2 * (in[4] * in[8] + 2 * (in[5] * in[7] + in[3] * in[9]));
    out[13] = 2 * (in[6] * in[7] + in[5] * in[8] + in[4] * in[9]);
    out[14] = 2 * (in[7] * in[7] + in[6] * in[8] + 2 *  in[5] * in[9]);
    out[15] = 2 * (in[7] * in[8] + in[6] * in[9]);
    out[16] = in[8] * in[8] + 4 * in[7] * in[9];
    out[17] = 2 *  in[8] * in[9];
    out[18] = 2 *  in[9] * in[9];
  }

  /**
   * Returns in^2.
   *
   * On entry: The |in| argument is in reduced coefficients form and |in[i]| < 2^27.
   *
   * On exit: The |output| argument is in reduced coefficients form (indeed, one need only provide
   * storage for 10 limbs) and |out[i]| < 2^26.
   */
  private static void square(long[] output, long[] in) {
    long[] t = new long[19];
    squareInner(t, in);
    // |t[i]| < 14*2^54 because the largest product of two limbs will be < 2^(27+27) and SquareInner
    // adds together, at most, 14 of those products.
    reduceDegree(t);
    reduceCoefficients(t);
    // |t[i]| < 2^26
    System.arraycopy(t, 0, output, 0, LIMB_CNT);
  }

  /**
   * Takes a little-endian, 32-byte number and expands it into polynomial form.
   */
  private static long[] expand(byte[] input) {
    long[] output = new long[LIMB_CNT];
    for (int i = 0; i < LIMB_CNT; i++) {
      output[i] = ((((long) (input[EXPAND_START[i]] & 0xff))
          | ((long) (input[EXPAND_START[i] + 1] & 0xff)) << 8
          | ((long) (input[EXPAND_START[i] + 2] & 0xff)) << 16
          | ((long) (input[EXPAND_START[i] + 3] & 0xff)) << 24) >> EXPAND_SHIFT[i]) & MASK[i & 1];
    }
    return output;
  }

  /**
   * Returns 0xffffffff iff a == b and zero otherwise.
   */
  private static int eq(int a, int b) {
    a = ~(a ^ b);
    a &= a << 16;
    a &= a << 8;
    a &= a << 4;
    a &= a << 2;
    a &= a << 1;
    return a >> 31;
  }

  /**
   * returns 0xffffffff if a >= b and zero otherwise, where a and b are both non-negative.
   */
  private static int gte(int a, int b) {
    a -= b;
    // a >= 0 iff a >= b.
    return ~(a >> 31);
  }

  /**
   * Takes a fully reduced polynomial form number and contract it into a little-endian, 32-byte
   * array.
   *
   * On entry: |input_limbs[i]| < 2^26
   */
  @SuppressWarnings("NarrowingCompoundAssignment")
  private static byte[] contract(long[] inputLimbs) {
    long[] input = Arrays.copyOf(inputLimbs, LIMB_CNT);
    for (int j = 0; j < 2; j++) {
      for (int i = 0; i < 9; i++) {
        // This calculation is a time-invariant way to make input[i] non-negative by borrowing
        // from the next-larger limb.
        int carry = -(int) ((input[i] & (input[i] >> 31)) >> SHIFT[i & 1]);
        input[i] = input[i] + (carry << SHIFT[i & 1]);
        input[i + 1] -= carry;
      }

      // There's no greater limb for input[9] to borrow from, but we can multiply by 19 and borrow
      // from input[0], which is valid mod 2^255-19.
      {
        int carry = -(int) ((input[9] & (input[9] >> 31)) >> 25);
        input[9] += (carry << 25);
        input[0] -= (carry * 19);
      }

      // After the first iteration, input[1..9] are non-negative and fit within 25 or 26 bits,
      // depending on position. However, input[0] may be negative.
    }

    // The first borrow-propagation pass above ended with every limb except (possibly) input[0]
    // non-negative.
    //
    // If input[0] was negative after the first pass, then it was because of a carry from input[9].
    // On entry, input[9] < 2^26 so the carry was, at most, one, since (2**26-1) >> 25 = 1. Thus
    // input[0] >= -19.
    //
    // In the second pass, each limb is decreased by at most one. Thus the second borrow-propagation
    // pass could only have wrapped around to decrease input[0] again if the first pass left
    // input[0] negative *and* input[1] through input[9] were all zero.  In that case, input[1] is
    // now 2^25 - 1, and this last borrow-propagation step will leave input[1] non-negative.
    {
      int carry = -(int) ((input[0] & (input[0] >> 31)) >> 26);
      input[0] += (carry << 26);
      input[1] -= carry;
    }

    // All input[i] are now non-negative. However, there might be values between 2^25 and 2^26 in a
    // limb which is, nominally, 25 bits wide.
    for (int j = 0; j < 2; j++) {
      for (int i = 0; i < 9; i++) {
        int carry = (int) (input[i] >> SHIFT[i & 1]);
        input[i] &= MASK[i & 1];
        input[i + 1] += carry;
      }
    }

    {
      int carry = (int) (input[9] >> 25);
      input[9] &= 0x1ffffff;
      input[0] += 19 * carry;
    }

    // If the first carry-chain pass, just above, ended up with a carry from input[9], and that
    // caused input[0] to be out-of-bounds, then input[0] was < 2^26 + 2*19, because the carry was,
    // at most, two.
    //
    // If the second pass carried from input[9] again then input[0] is < 2*19 and the input[9] ->
    // input[0] carry didn't push input[0] out of bounds.

    // It still remains the case that input might be between 2^255-19 and 2^255. In this case,
    // input[1..9] must take their maximum value and input[0] must be >= (2^255-19) & 0x3ffffff,
    // which is 0x3ffffed.
    int mask = gte((int) input[0], 0x3ffffed);
    for (int i = 1; i < LIMB_CNT; i++) {
      mask &= eq((int) input[i], MASK[i & 1]);
    }

    // mask is either 0xffffffff (if input >= 2^255-19) and zero otherwise. Thus this conditionally
    // subtracts 2^255-19.
    input[0] -= mask & 0x3ffffed;
    input[1] -= mask & 0x1ffffff;
    for (int i = 2; i < LIMB_CNT; i += 2) {
      input[i] -= mask & 0x3ffffff;
      input[i + 1] -= mask & 0x1ffffff;
    }

    for (int i = 0; i < LIMB_CNT; i++) {
      input[i] <<= EXPAND_SHIFT[i];
    }
    byte[] output = new byte[BYTE_LEN];
    for (int i = 0; i < LIMB_CNT; i++) {
      output[EXPAND_START[i]] |= input[i] & 0xff;
      output[EXPAND_START[i] + 1] |= (input[i] >> 8) & 0xff;
      output[EXPAND_START[i] + 2] |= (input[i] >> 16) & 0xff;
      output[EXPAND_START[i] + 3] |= (input[i] >> 24) & 0xff;
    }
    return output;
  }

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
    long[] origx = Arrays.copyOf(x, LIMB_CNT);
    long[] zzz = new long[19];
    long[] xx = new long[19];
    long[] zz = new long[19];
    long[] xxprime = new long[19];
    long[] zzprime = new long[19];
    long[] zzzprime = new long[19];
    long[] xxxprime = new long[19];

    sum(x, z);
    // |x[i]| < 2^27
    sub(z, origx);  // does x - z
    // |z[i]| < 2^27

    long[] origxprime = Arrays.copyOf(xprime, LIMB_CNT);
    sum(xprime, zprime);
    // |xprime[i]| < 2^27
    sub(zprime, origxprime);
    // |zprime[i]| < 2^27
    product(xxprime, xprime, z);
    // |xxprime[i]| < 14*2^54: the largest product of two limbs will be < 2^(27+27) and fproduct
    // adds together, at most, 14 of those products. (Approximating that to 2^58 doesn't work out.)
    product(zzprime, x, zprime);
    // |zzprime[i]| < 14*2^54
    reduceDegree(xxprime);
    reduceCoefficients(xxprime);
    // |xxprime[i]| < 2^26
    reduceDegree(zzprime);
    reduceCoefficients(zzprime);
    // |zzprime[i]| < 2^26
    System.arraycopy(xxprime, 0, origxprime, 0, LIMB_CNT);
    sum(xxprime, zzprime);
    // |xxprime[i]| < 2^27
    sub(zzprime, origxprime);
    // |zzprime[i]| < 2^27
    square(xxxprime, xxprime);
    // |xxxprime[i]| < 2^26
    square(zzzprime, zzprime);
    // |zzzprime[i]| < 2^26
    product(zzprime, zzzprime, qmqp);
    // |zzprime[i]| < 14*2^52
    reduceDegree(zzprime);
    reduceCoefficients(zzprime);
    // |zzprime[i]| < 2^26
    System.arraycopy(xxxprime, 0, x3, 0, LIMB_CNT);
    System.arraycopy(zzprime, 0, z3, 0, LIMB_CNT);

    square(xx, x);
    // |xx[i]| < 2^26
    square(zz, z);
    // |zz[i]| < 2^26
    product(x2, xx, zz);
    // |x2[i]| < 14*2^52
    reduceDegree(x2);
    reduceCoefficients(x2);
    // |x2[i]| < 2^26
    sub(zz, xx);  // does zz = xx - zz
    // |zz[i]| < 2^27
    Arrays.fill(zzz, LIMB_CNT, zzz.length - 1, 0);
    scalarProduct(zzz, zz, 121665);
    // |zzz[i]| < 2^(27+17)
    // No need to call reduceDegree here: scalarProduct doesn't increase the degree of its input.
    reduceCoefficients(zzz);
    // |zzz[i]| < 2^26
    sum(zzz, xx);
    // |zzz[i]| < 2^27
    product(z2, zz, zzz);
    // |z2[i]| < 14*2^(26+27)
    reduceDegree(z2);
    reduceCoefficients(z2);
    // |z2|i| < 2^26
  }

  /**
   * Conditionally swap two reduced-form limb arrays if 'iswap' is 1, but leave them unchanged if
   * 'iswap' is 0.  Runs in data-invariant time to avoid side-channel attacks.
   *
   * NOTE that this function requires that 'iswap' be 1 or 0; other values give wrong results.
   * Also, the two limb arrays must be in reduced-coefficient, reduced-degree form: the values in
   * a[10..19] or b[10..19] aren't swapped, and all all values in a[0..9],b[0..9] must have
   * magnitude less than Integer.MAX_VALUE.
   */
  private static void swapConditional(long[] a, long[] b, int iswap) {
    int swap = -iswap;
    for (int i = 0; i < LIMB_CNT; i++) {
      int x = swap & (((int) a[i]) ^ ((int) b[i]));
      a[i] = ((int) a[i]) ^ x;
      b[i] = ((int) b[i]) ^ x;
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

    System.arraycopy(q, 0, nqpqx, 0, LIMB_CNT);

    for (int i = 0; i < BYTE_LEN; i++) {
      int b = n[BYTE_LEN - i - 1] & 0xff;
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

    System.arraycopy(nqx, 0, resultx, 0, LIMB_CNT);
    System.arraycopy(nqz, 0, resultz, 0, LIMB_CNT);
  }

  /**
   * Computes inverse of z = z(2^255 - 21)
   *
   * Shamelessly copied from agl's code which was shamelessly copied from djb's code. Only the
   * comment format and the variable namings are different from those.
   */
  private static void curveRecip(long[] out, long[] z) {
    long[] z2 = new long[10];
    long[] z9 = new long[10];
    long[] z11 = new long[10];
    long[] z2To5Minus1 = new long[10];
    long[] z2To10Minus1 = new long[10];
    long[] z2To20Minus1 = new long[10];
    long[] z2To50Minus1 = new long[10];
    long[] z2To100Minus1 = new long[10];
    long[] t0 = new long[10];
    long[] t1 = new long[10];

    square(z2, z);                          // 2
    square(t1, z2);                         // 4
    square(t0, t1);                         // 8
    mult(z9, t0, z);                        // 9
    mult(z11, z9, z2);                      // 11
    square(t0, z11);                        // 22
    mult(z2To5Minus1, t0, z9);              // 2^5 - 2^0 = 31

    square(t0, z2To5Minus1);                // 2^6 - 2^1
    square(t1, t0);                         // 2^7 - 2^2
    square(t0, t1);                         // 2^8 - 2^3
    square(t1, t0);                         // 2^9 - 2^4
    square(t0, t1);                         // 2^10 - 2^5
    mult(z2To10Minus1, t0, z2To5Minus1);    // 2^10 - 2^0

    square(t0, z2To10Minus1);               // 2^11 - 2^1
    square(t1, t0);                         // 2^12 - 2^2
    for (int i = 2; i < 10; i += 2) {       // 2^20 - 2^10
      square(t0, t1);
      square(t1, t0);
    }
    mult(z2To20Minus1, t1, z2To10Minus1);   // 2^20 - 2^0

    square(t0, z2To20Minus1);               // 2^21 - 2^1
    square(t1, t0);                         // 2^22 - 2^2
    for (int i = 2; i < 20; i += 2) {       // 2^40 - 2^20
      square(t0, t1);
      square(t1, t0);
    }
    mult(t0, t1, z2To20Minus1);             // 2^40 - 2^0

    square(t1, t0);                         // 2^41 - 2^1
    square(t0, t1);                         // 2^42 - 2^2
    for (int i = 2; i < 10; i += 2) {       // 2^50 - 2^10
      square(t1, t0);
      square(t0, t1);
    }
    mult(z2To50Minus1, t0, z2To10Minus1);   // 2^50 - 2^0

    square(t0, z2To50Minus1);               // 2^51 - 2^1
    square(t1, t0);                         // 2^52 - 2^2
    for (int i = 2; i < 50; i += 2) {       // 2^100 - 2^50
      square(t0, t1);
      square(t1, t0);
    }
    mult(z2To100Minus1, t1, z2To50Minus1);  // 2^100 - 2^0

    square(t1, z2To100Minus1);              // 2^101 - 2^1
    square(t0, t1);                         // 2^102 - 2^2
    for (int i = 2; i < 100; i += 2) {      // 2^200 - 2^100
      square(t1, t0);
      square(t0, t1);
    }
    mult(t1, t0, z2To100Minus1);            // 2^200 - 2^0

    square(t0, t1);                         // 2^201 - 2^1
    square(t1, t0);                         // 2^202 - 2^2
    for (int i = 2; i < 50; i += 2) {       // 2^250 - 2^50
      square(t0, t1);
      square(t1, t0);
    }
    mult(t0, t1, z2To50Minus1);             // 2^250 - 2^0

    square(t1, t0);                         // 2^251 - 2^1
    square(t0, t1);                         // 2^252 - 2^2
    square(t1, t0);                         // 2^253 - 2^3
    square(t0, t1);                         // 2^254 - 2^4
    square(t1, t0);                         // 2^255 - 2^5
    mult(out, t1, z11);                     // 2^255 - 21
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
    byte[] privateKey = Random.randBytes(BYTE_LEN);

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
    checkArgument(privateKey.length == BYTE_LEN, "Private key must have 32 bytes.");
    checkArgument(peersPublicValue.length == BYTE_LEN, "Peer's public key must have 32 bytes.");
    long[] x = new long[LIMB_CNT];
    long[] z = new long[LIMB_CNT + 1];
    long[] zmone = new long[LIMB_CNT];

    byte[] e = Arrays.copyOf(privateKey, BYTE_LEN);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    long[] bp = expand(peersPublicValue);
    curveMult(x, z, e, bp);
    curveRecip(zmone, z);
    mult(z, x, zmone);
    return contract(z);
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
    checkArgument(privateKey.length == BYTE_LEN, "Private key must have 32 bytes.");
    byte[] base = new byte[BYTE_LEN]; base[0] = 9;
    return x25519(privateKey, base);
  }
}
