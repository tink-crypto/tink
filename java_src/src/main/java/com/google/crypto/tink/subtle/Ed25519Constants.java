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

/** Constants used in {@link Ed25519}. */
final class Ed25519Constants {

 // d = -121665 / 121666 mod 2^255-19
  static final long[] D;
  // 2d
  static final long[] D2;
  // 2^((p-1)/4) mod p where p = 2^255-19
  static final long[] SQRTM1;

  /**
   * Base point for the Edwards twisted curve = (x, 4/5) and its exponentiations. B_TABLE[i][j] =
   * (j+1)*256^i*B for i in [0, 32) and j in [0, 8). Base point B = B_TABLE[0][0]
   *
   * <p>See {@link Ed25519ConstantsGenerator}.
   */
  static final Ed25519.CachedXYT[][] B_TABLE;
  static final Ed25519.CachedXYT[] B2;

  private static final BigInteger P_BI =
      BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
  private static final BigInteger D_BI =
      BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P_BI)).mod(P_BI);
  private static final BigInteger D2_BI = BigInteger.valueOf(2).multiply(D_BI).mod(P_BI);
  private static final BigInteger SQRTM1_BI =
      BigInteger.valueOf(2).modPow(P_BI.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P_BI);

  private static class Point {
    private BigInteger x;
    private BigInteger y;
  }

  private static BigInteger recoverX(BigInteger y) {
    // x^2 = (y^2 - 1) / (d * y^2 + 1) mod 2^255-19
    BigInteger xx =
        y.pow(2)
            .subtract(BigInteger.ONE)
            .multiply(D_BI.multiply(y.pow(2)).add(BigInteger.ONE).modInverse(P_BI));
    BigInteger x = xx.modPow(P_BI.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P_BI);
    if (!x.pow(2).subtract(xx).mod(P_BI).equals(BigInteger.ZERO)) {
      x = x.multiply(SQRTM1_BI).mod(P_BI);
    }
    if (x.testBit(0)) {
      x = P_BI.subtract(x);
    }
    return x;
  }

  private static Point edwards(Point a, Point b) {
    Point o = new Point();
    BigInteger xxyy = D_BI.multiply(a.x.multiply(b.x).multiply(a.y).multiply(b.y)).mod(P_BI);
    o.x =
        (a.x.multiply(b.y).add(b.x.multiply(a.y)))
            .multiply(BigInteger.ONE.add(xxyy).modInverse(P_BI))
            .mod(P_BI);
    o.y =
        (a.y.multiply(b.y).add(a.x.multiply(b.x)))
            .multiply(BigInteger.ONE.subtract(xxyy).modInverse(P_BI))
            .mod(P_BI);
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

  private static Ed25519.CachedXYT getCachedXYT(Point p) {
    return new Ed25519.CachedXYT(
        Field25519.expand(toLittleEndian(p.y.add(p.x).mod(P_BI))),
        Field25519.expand(toLittleEndian(p.y.subtract(p.x).mod(P_BI))),
        Field25519.expand(toLittleEndian(D2_BI.multiply(p.x).multiply(p.y).mod(P_BI))));
  }

  static {
    Point b = new Point();
    b.y = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P_BI)).mod(P_BI);
    b.x = recoverX(b.y);

    D = Field25519.expand(toLittleEndian(D_BI));
    D2 = Field25519.expand(toLittleEndian(D2_BI));
    SQRTM1 = Field25519.expand(toLittleEndian(SQRTM1_BI));

    Point bi = b;
    B_TABLE = new Ed25519.CachedXYT[32][8];
    for (int i = 0; i < 32; i++) {
      Point bij = bi;
      for (int j = 0; j < 8; j++) {
        B_TABLE[i][j] = getCachedXYT(bij);
        bij = edwards(bij, bi);
      }
      for (int j = 0; j < 8; j++) {
        bi = edwards(bi, bi);
      }
    }
    bi = b;
    Point b2 = edwards(b, b);
    B2 = new Ed25519.CachedXYT[8];
    for (int i = 0; i < 8; i++) {
      B2[i] = getCachedXYT(bi);
      bi = edwards(bi, b2);
    }
  }

  private Ed25519Constants() {}
}
