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

import java.math.BigInteger;
import java.util.Arrays;

/** Generates constants used in {@link Ed25519}. */
public final class Ed25519ConstantsGenerator {

  private static final BigInteger P =
      BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
  private static final BigInteger D =
      BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
  private static final BigInteger D2 = BigInteger.valueOf(2).multiply(D).mod(P);
  private static final BigInteger SQRTM1 =
      BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);

  private static class Point {
    private BigInteger x;
    private BigInteger y;
  }

  private static BigInteger recoverX(BigInteger y) {
    // x^2 = (y^2 - 1) / (d * y^2 + 1) mod 2^255-19
    BigInteger xx =
        y.pow(2)
            .subtract(BigInteger.ONE)
            .multiply(D.multiply(y.pow(2)).add(BigInteger.ONE).modInverse(P));
    BigInteger x = xx.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P);
    if (!x.pow(2).subtract(xx).mod(P).equals(BigInteger.ZERO)) {
      x = x.multiply(SQRTM1).mod(P);
    }
    if (x.testBit(0)) {
      x = P.subtract(x);
    }
    return x;
  }

  private static Point edwards(Point a, Point b) {
    Point o = new Point();
    o.x =
        (a.x.multiply(b.y).add(b.x.multiply(a.y)))
            .multiply(
                BigInteger.ONE
                    .add(D.multiply(a.x.multiply(b.x).multiply(a.y).multiply(b.y)))
                    .modInverse(P))
            .mod(P);
    o.y =
        (a.y.multiply(b.y).add(a.x.multiply(b.x)))
            .multiply(
                BigInteger.ONE
                    .subtract(D.multiply(a.x.multiply(b.x).multiply(a.y).multiply(b.y)))
                    .modInverse(P))
            .mod(P);
    return o;
  }

  private static byte[] toLittleEndian(BigInteger n) {
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

  private static String replaceBrackets(String array) {
    return array.replace("[", "{").replace("]", "}");
  }

  private static String getCachedXYTStr(Point p) {
    String decl = "new CachedXYT(\n";
    decl +=
        "new long[]"
            + replaceBrackets(
                Arrays.toString(Field25519.expand(toLittleEndian(p.y.add(p.x).mod(P)))))
            + ",\n";
    decl +=
        "new long[]"
            + replaceBrackets(
                Arrays.toString(Field25519.expand(toLittleEndian(p.y.subtract(p.x).mod(P)))))
            + ",\n";
    decl +=
        "new long[]"
            + replaceBrackets(
                Arrays.toString(
                    Field25519.expand(toLittleEndian(D2.multiply(p.x).multiply(p.y).mod(P)))))
            + ")";
    return decl;
  }

  public static void main(String[] args) {
    Point b = new Point();
    b.y = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P);
    b.x = recoverX(b.y);
    String decl = "static final long[]";

    System.out.println("// d = -121665 / 121666 mod 2^255-19");
    System.out.println(
        decl
            + " D = "
            + replaceBrackets(Arrays.toString(Field25519.expand(toLittleEndian(D))))
            + ";");
    System.out.println("// 2d");
    System.out.println(
        decl
            + " D2 = "
            + replaceBrackets(Arrays.toString(Field25519.expand(toLittleEndian(D2))))
            + ";");
    System.out.println("// 2^((p-1)/4) mod p where p = 2^255-19");
    System.out.println(
        decl
            + " SQRTM1 = "
            + replaceBrackets(Arrays.toString(Field25519.expand(toLittleEndian(SQRTM1))))
            + ";");
    // System.out.println("// (x, 4/5)");
    Point bi = b;
    System.out.println("static final CachedXYT[][] B_TABLE = new CachedXYT[][]{");
    for (int i = 0; i < 32; i++) {
      System.out.println("{");
      Point bij = bi;
      for (int j = 0; j < 8; j++) {
        System.out.println(getCachedXYTStr(bij) + ",");
        bij = edwards(bij, bi);
      }
      System.out.println("},");
      for (int j = 0; j < 8; j++) {
        bi = edwards(bi, bi);
      }
    }
    System.out.println("};");
    bi = b;
    Point b2 = edwards(b, b);
    System.out.println("static final CachedXYT[] B2 = new CachedXYT[]{");
    for (int i = 0; i < 8; i++) {
      System.out.println(getCachedXYTStr(bi) + ",");
      bi = edwards(bi, b2);
    }
    System.out.println("};");
  }
}
