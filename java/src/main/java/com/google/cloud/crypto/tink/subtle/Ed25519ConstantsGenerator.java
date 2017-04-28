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

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Generates constants used in {@link Ed25519}.
 */
public class Ed25519ConstantsGenerator {

  private static BigInteger P = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
  private static BigInteger D = BigInteger.valueOf(-121665).multiply(
      BigInteger.valueOf(121666).modInverse(P)).mod(P);
  private static BigInteger D2 = BigInteger.valueOf(2).multiply(D).mod(P);
  private static BigInteger SQRTM1 = BigInteger.valueOf(2).modPow(
      P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);

  private static class Point {
    private BigInteger x;
    private BigInteger y;
  }

  private static BigInteger recoverX(BigInteger y) {
    // x^2 = (y^2 - 1) / (d * y^2 + 1) mod 2^255-19
    BigInteger xx = y.pow(2).subtract(BigInteger.ONE)
        .multiply(D.multiply(y.pow(2)).add(BigInteger.ONE).modInverse(P));
    BigInteger x = xx.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P);
    if (x.pow(2).subtract(xx).mod(P) != BigInteger.ZERO) {
      x = x.multiply(SQRTM1).mod(P);
    }
    if (x.testBit(0)) {
      x = P.subtract(x);
    }
    return x;
  }

  private static byte[] toLittleEndian(BigInteger n) {
    byte[] b = n.toByteArray();
    for (int i = 0; i < b.length / 2; i++) {
      byte t = b[i];
      b[i] = b[b.length - i - 1];
      b[b.length - i - 1] = t;
    }
    return b;
  }

  private static String replaceBrackets(String array) {
    return array.replace("[", "{").replace("]", "}");
  }

  public static void main(String[] args) {
    Point b = new Point();
    b.y = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P);
    b.x = recoverX(b.y);
    String decl = "private static final long[]";

    System.out.println("// d = -121665 / 121666 mod 2^255-19");
    System.out.println(decl + " D = "
        + replaceBrackets(Arrays.toString(Curve25519.expand(toLittleEndian(D)))) + ";");
    System.out.println("// 2d");
    System.out.println(decl + " D2 = "
        + replaceBrackets(Arrays.toString(Curve25519.expand(toLittleEndian(D2)))) + ";");
    System.out.println("// 2^((p-1)/4) mod p where p = 2^255-19");
    System.out.println(decl + " SQRTM1 = "
        + replaceBrackets(Arrays.toString(Curve25519.expand(toLittleEndian(SQRTM1)))) + ";");
    System.out.println("// (x, 4/5)");
    System.out.println("private static final CachedXYT B = new CachedXYT(");
    System.out.println("new long[]"
        + replaceBrackets(
            Arrays.toString(Curve25519.expand(toLittleEndian(b.y.add(b.x).mod(P))))) + ",");
    System.out.println("new long[]"
        + replaceBrackets(
            Arrays.toString(Curve25519.expand(toLittleEndian(b.y.subtract(b.x).mod(P))))) + ",");
    System.out.println("new long[]"
        + replaceBrackets(
            Arrays.toString(
                Curve25519.expand(toLittleEndian(D2.multiply(b.x).multiply(b.y).mod(P))))) + ");");
  }
}
