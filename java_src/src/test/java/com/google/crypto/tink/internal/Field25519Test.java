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

package com.google.crypto.tink.internal;

import static com.google.crypto.tink.internal.Field25519.FIELD_LEN;
import static com.google.crypto.tink.internal.Field25519.LIMB_CNT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link Field25519}.
 *
 * <p>TODO(quannguyen): Add more tests. Note that several functions assume that the inputs are in
 * reduced forms, so testing them don't guarantee that its uses are safe. There may be integer
 * overflow when they aren't used correctly.
 */
@RunWith(JUnit4.class)
public final class Field25519Test {
  /**
   * The idea of basic tests is simple. We generate random numbers, make computations with
   * Field25519 and compare the results with Java BigInteger.
   */
  private static final int NUM_BASIC_TESTS = 1024;

  private static final SecureRandom rand = new SecureRandom();
  private static final BigInteger P =
      BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
  BigInteger[] x = new BigInteger[NUM_BASIC_TESTS];
  BigInteger[] y = new BigInteger[NUM_BASIC_TESTS];

  @Before
  public void setUp() {
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      x[i] = (new BigInteger(FIELD_LEN * 8, rand)).mod(P);
      y[i] = (new BigInteger(FIELD_LEN * 8, rand)).mod(P);
    }
  }

  @Test
  public void testBasicSum() {
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      BigInteger expectedResult = x[i].add(y[i]).mod(P);
      byte[] xBytes = toLittleEndian(x[i]);
      byte[] yBytes = toLittleEndian(y[i]);
      long[] output = new long[LIMB_CNT * 2 + 1];
      Field25519.sum(output, Field25519.expand(xBytes), Field25519.expand(yBytes));
      Field25519.reduceCoefficients(output);
      BigInteger result = new BigInteger(reverse(Field25519.contract(output)));
      assertEquals("Sum x[i] + y[i]: " + x[i] + "+" + y[i], expectedResult, result);
    }
  }

  @Test
  public void testBasicSub() {
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      BigInteger expectedResult = x[i].subtract(y[i]).mod(P);
      byte[] xBytes = toLittleEndian(x[i]);
      byte[] yBytes = toLittleEndian(y[i]);
      long[] output = new long[LIMB_CNT * 2 + 1];
      Field25519.sub(output, Field25519.expand(xBytes), Field25519.expand(yBytes));
      Field25519.reduceCoefficients(output);
      BigInteger result = new BigInteger(reverse(Field25519.contract(output)));
      assertEquals("Subtraction x[i] - y[i]: " + x[i] + "-" + y[i], expectedResult, result);
    }
  }

  @Test
  public void testBasicProduct() {
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      BigInteger expectedResult = x[i].multiply(y[i]).mod(P);
      byte[] xBytes = toLittleEndian(x[i]);
      byte[] yBytes = toLittleEndian(y[i]);
      long[] output = new long[LIMB_CNT * 2 + 1];
      Field25519.product(output, Field25519.expand(xBytes), Field25519.expand(yBytes));
      Field25519.reduceSizeByModularReduction(output);
      Field25519.reduceCoefficients(output);
      BigInteger result = new BigInteger(reverse(Field25519.contract(output)));
      assertEquals("Product x[i] * y[i]: " + x[i] + "*" + y[i], expectedResult, result);
    }
  }

  @Test
  public void testBasicMult() {
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      BigInteger expectedResult = x[i].multiply(y[i]).mod(P);
      byte[] xBytes = toLittleEndian(x[i]);
      byte[] yBytes = toLittleEndian(y[i]);
      long[] output = new long[LIMB_CNT * 2 + 1];
      Field25519.mult(output, Field25519.expand(xBytes), Field25519.expand(yBytes));
      BigInteger result = new BigInteger(reverse(Field25519.contract(output)));
      assertEquals("Multiplication x[i] * y[i]: " + x[i] + "*" + y[i], expectedResult, result);
    }
  }

  @Test
  public void testBasicScalarProduct() {
    final long scalar = 121665;
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      BigInteger expectedResult = x[i].multiply(BigInteger.valueOf(scalar)).mod(P);
      byte[] xBytes = toLittleEndian(x[i]);
      long[] output = new long[LIMB_CNT * 2 + 1];
      Field25519.scalarProduct(output, Field25519.expand(xBytes), scalar);
      Field25519.reduceSizeByModularReduction(output);
      Field25519.reduceCoefficients(output);
      BigInteger result = new BigInteger(reverse(Field25519.contract(output)));
      assertEquals("Scalar product x[i] * 10 " + x[i] + "*" + 10, expectedResult, result);
    }
  }

  @Test
  public void testBasicSquare() {
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      BigInteger expectedResult = x[i].multiply(x[i]).mod(P);
      byte[] xBytes = toLittleEndian(x[i]);
      long[] output = new long[LIMB_CNT * 2 + 1];
      Field25519.square(output, Field25519.expand(xBytes));
      Field25519.reduceSizeByModularReduction(output);
      Field25519.reduceCoefficients(output);
      BigInteger result = new BigInteger(reverse(Field25519.contract(output)));
      assertEquals("Square x[i] * x[i]: " + x[i] + "*" + x[i], expectedResult, result);
    }
  }

  @Test
  public void testBasicInverse() {
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      BigInteger expectedResult = x[i].modInverse(P);
      byte[] xBytes = toLittleEndian(x[i]);
      long[] output = new long[LIMB_CNT * 2 + 1];
      Field25519.inverse(output, Field25519.expand(xBytes));
      BigInteger result = new BigInteger(reverse(Field25519.contract(output)));
      assertEquals("Inverse: x[i]^(-1) mod P: " + x[i], expectedResult, result);
    }
  }

  @Test
  public void testContractExpand() {
    for (int i = 0; i < NUM_BASIC_TESTS; i++) {
      byte[] xBytes = toLittleEndian(x[i]);
      byte[] result = Field25519.contract(Field25519.expand(xBytes));
      assertArrayEquals(xBytes, result);
    }
  }

  private byte[] toLittleEndian(BigInteger n) {
    byte[] b = new byte[32];
    byte[] nBytes = n.toByteArray();
    System.arraycopy(nBytes, 0, b, 32 - nBytes.length, nBytes.length);
    for (int i = 0; i < b.length / 2; i++) {
      byte t = b[i];
      b[i] = b[b.length - i - 1];
      b[b.length - i - 1] = t;
    }
    return b;
  }

  private byte[] reverse(byte[] x) {
    byte[] r = new byte[x.length];
    for (int i = 0; i < x.length; i++) {
      r[i] = x[x.length - i - 1];
    }
    return r;
  }
}
