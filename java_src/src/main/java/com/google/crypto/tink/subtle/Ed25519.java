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

import static com.google.crypto.tink.subtle.Ed25519Constants.B2;
import static com.google.crypto.tink.subtle.Ed25519Constants.B_TABLE;
import static com.google.crypto.tink.subtle.Ed25519Constants.D;
import static com.google.crypto.tink.subtle.Ed25519Constants.D2;
import static com.google.crypto.tink.subtle.Ed25519Constants.SQRTM1;
import static com.google.crypto.tink.subtle.Field25519.FIELD_LEN;
import static com.google.crypto.tink.subtle.Field25519.LIMB_CNT;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * This implementation is based on the ed25519/ref10 implementation in NaCl.
 *
 * <p>It implements this twisted Edwards curve:
 *
 * <pre>
 * -x^2 + y^2 = 1 + (-121665 / 121666 mod 2^255-19)*x^2*y^2
 * </pre>
 *
 * @see <a href="https://eprint.iacr.org/2008/013.pdf">Bernstein D.J., Birkner P., Joye M., Lange
 *     T., Peters C. (2008) Twisted Edwards Curves</a>
 * @see <a href="https://eprint.iacr.org/2008/522.pdf">Hisil H., Wong K.KH., Carter G., Dawson E.
 *     (2008) Twisted Edwards Curves Revisited</a>
 */
final class Ed25519 {

  public static final int SECRET_KEY_LEN = FIELD_LEN;
  public static final int PUBLIC_KEY_LEN = FIELD_LEN;
  public static final int SIGNATURE_LEN = FIELD_LEN * 2;

  // (x = 0, y = 1) point
  private static final CachedXYT CACHED_NEUTRAL = new CachedXYT(
      new long[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      new long[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      new long[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  private static final PartialXYZT NEUTRAL = new PartialXYZT(
      new XYZ(new long[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
          new long[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
          new long[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
      new long[]{1, 0, 0, 0, 0, 0, 0, 0, 0, 0});

  /**
   * Projective point representation (X:Y:Z) satisfying x = X/Z, y = Y/Z
   *
   * Note that this is referred as ge_p2 in ref10 impl.
   * Also note that x = X, y = Y and z = Z below following Java coding style.
   *
   * See
   * Koyama K., Tsuruoka Y. (1993) Speeding up Elliptic Cryptosystems by Using a Signed Binary
   * Window Method.
   *
   * https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
   */
  private static class XYZ {

    final long[] x;
    final long[] y;
    final long[] z;

    XYZ() {
      this(new long[LIMB_CNT], new long[LIMB_CNT], new long[LIMB_CNT]);
    }

    XYZ(long[] x, long[] y, long[] z) {
      this.x = x;
      this.y = y;
      this.z = z;
    }

    XYZ(XYZ xyz) {
      x = Arrays.copyOf(xyz.x, LIMB_CNT);
      y = Arrays.copyOf(xyz.y, LIMB_CNT);
      z = Arrays.copyOf(xyz.z, LIMB_CNT);
    }

    XYZ(PartialXYZT partialXYZT) {
      this();
      fromPartialXYZT(this, partialXYZT);
    }

    /**
     * ge_p1p1_to_p2.c
     */
    static XYZ fromPartialXYZT(XYZ out, PartialXYZT in) {
      Field25519.mult(out.x, in.xyz.x, in.t);
      Field25519.mult(out.y, in.xyz.y, in.xyz.z);
      Field25519.mult(out.z, in.xyz.z, in.t);
      return out;
    }

    /**
     * Encodes this point to bytes.
     */
    byte[] toBytes() {
      long[] recip = new long[LIMB_CNT];
      long[] x = new long[LIMB_CNT];
      long[] y = new long[LIMB_CNT];
      Field25519.inverse(recip, z);
      Field25519.mult(x, this.x, recip);
      Field25519.mult(y, this.y, recip);
      byte[] s = Field25519.contract(y);
      s[31] = (byte) (s[31] ^ (getLsb(x) << 7));
      return s;
    }

    /** Checks that the point is on curve */
    boolean isOnCurve() {
      long[] x2 = new long[LIMB_CNT];
      Field25519.square(x2, x);
      long[] y2 = new long[LIMB_CNT];
      Field25519.square(y2, y);
      long[] z2 = new long[LIMB_CNT];
      Field25519.square(z2, z);
      long[] z4 = new long[LIMB_CNT];
      Field25519.square(z4, z2);
      long[] lhs = new long[LIMB_CNT];
      // lhs = y^2 - x^2
      Field25519.sub(lhs, y2, x2);
      // lhs = z^2 * (y2 - x2)
      Field25519.mult(lhs, lhs, z2);
      long[] rhs = new long[LIMB_CNT];
      // rhs = x^2 * y^2
      Field25519.mult(rhs, x2, y2);
      // rhs = D * x^2 * y^2
      Field25519.mult(rhs, rhs, D);
      // rhs = z^4 + D * x^2 * y^2
      Field25519.sum(rhs, z4);
      // Field25519.mult reduces its output, but Field25519.sum does not, so we have to manually
      // reduce it here.
      Field25519.reduce(rhs, rhs);
      // z^2 (y^2 - x^2) == z^4 + D * x^2 * y^2
      return Bytes.equal(Field25519.contract(lhs), Field25519.contract(rhs));
    }
  }

  /**
   * Represents extended projective point representation (X:Y:Z:T) satisfying x = X/Z, y = Y/Z,
   * XY = ZT
   *
   * Note that this is referred as ge_p3 in ref10 impl.
   * Also note that t = T below following Java coding style.
   *
   * See
   * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
   *
   * https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html
   */
  private static class XYZT {

    final XYZ xyz;
    final long[] t;

    XYZT() {
      this(new XYZ(), new long[LIMB_CNT]);
    }

    XYZT(XYZ xyz, long[] t) {
      this.xyz = xyz;
      this.t = t;
    }

    XYZT(PartialXYZT partialXYZT) {
      this();
      fromPartialXYZT(this, partialXYZT);
    }

    /**
     * ge_p1p1_to_p2.c
     */
    private static XYZT fromPartialXYZT(XYZT out, PartialXYZT in) {
      Field25519.mult(out.xyz.x, in.xyz.x, in.t);
      Field25519.mult(out.xyz.y, in.xyz.y, in.xyz.z);
      Field25519.mult(out.xyz.z, in.xyz.z, in.t);
      Field25519.mult(out.t, in.xyz.x, in.xyz.y);
      return out;
    }

    /**
     * Decodes {@code s} into an extented projective point.
     * See Section 5.1.3 Decoding in https://tools.ietf.org/html/rfc8032#section-5.1.3
     */
    private static XYZT fromBytesNegateVarTime(byte[] s) throws GeneralSecurityException {
      long[] x = new long[LIMB_CNT];
      long[] y = Field25519.expand(s);
      long[] z = new long[LIMB_CNT]; z[0] = 1;
      long[] t = new long[LIMB_CNT];
      long[] u = new long[LIMB_CNT];
      long[] v = new long[LIMB_CNT];
      long[] vxx = new long[LIMB_CNT];
      long[] check = new long[LIMB_CNT];
      Field25519.square(u, y);
      Field25519.mult(v, u, D);
      Field25519.sub(u, u, z); // u = y^2 - 1
      Field25519.sum(v, v, z); // v = dy^2 + 1

      long[] v3 = new long[LIMB_CNT];
      Field25519.square(v3, v);
      Field25519.mult(v3, v3, v); // v3 = v^3
      Field25519.square(x, v3);
      Field25519.mult(x, x, v);
      Field25519.mult(x, x, u); // x = uv^7

      pow2252m3(x, x); // x = (uv^7)^((q-5)/8)
      Field25519.mult(x, x, v3);
      Field25519.mult(x, x, u); // x = uv^3(uv^7)^((q-5)/8)

      Field25519.square(vxx, x);
      Field25519.mult(vxx, vxx, v);
      Field25519.sub(check, vxx, u); // vx^2-u
      if (isNonZeroVarTime(check)) {
        Field25519.sum(check, vxx, u); // vx^2+u
        if (isNonZeroVarTime(check)) {
          throw new GeneralSecurityException("Cannot convert given bytes to extended projective "
              + "coordinates. No square root exists for modulo 2^255-19");
        }
        Field25519.mult(x, x, SQRTM1);
      }

      if (!isNonZeroVarTime(x) && (s[31] & 0xff) >> 7 != 0) {
        throw new GeneralSecurityException("Cannot convert given bytes to extended projective "
            + "coordinates. Computed x is zero and encoded x's least significant bit is not zero");
      }
      if (getLsb(x) == ((s[31] & 0xff) >> 7)) {
        neg(x, x);
      }

      Field25519.mult(t, x, y);
      return new XYZT(new XYZ(x, y, z), t);
    }
  }

  /**
   * Partial projective point representation ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
   *
   * Note that this is referred as complete form in the original ref10 impl (ge_p1p1).
   * Also note that t = T below following Java coding style.
   *
   * Although this has the same types as XYZT, it is redefined to have its own type so that it is
   * readable and 1:1 corresponds to ref10 impl.
   *
   * Can be converted to XYZT as follows:
   * X1 = X * T = x * Z * T = x * Z1
   * Y1 = Y * Z = y * T * Z = y * Z1
   * Z1 = Z * T = Z * T
   * T1 = X * Y = x * Z * y * T = x * y * Z1 = X1Y1 / Z1
   */
  private static class PartialXYZT {

    final XYZ xyz;
    final long[] t;

    PartialXYZT() {
      this(new XYZ(), new long[LIMB_CNT]);
    }

    PartialXYZT(XYZ xyz, long[] t) {
      this.xyz = xyz;
      this.t = t;
    }

    PartialXYZT(PartialXYZT other) {
      xyz = new XYZ(other.xyz);
      t = Arrays.copyOf(other.t, LIMB_CNT);
    }
  }

  /**
   * Corresponds to the caching mentioned in the last paragraph of Section 3.1 of
   * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
   * with Z = 1.
   */
  static class CachedXYT {

    final long[] yPlusX;
    final long[] yMinusX;
    final long[] t2d;

    CachedXYT() {
      this(new long[LIMB_CNT], new long[LIMB_CNT], new long[LIMB_CNT]);
    }

    /**
     * Creates a cached XYZT with Z = 1
     *
     * @param yPlusX y + x
     * @param yMinusX y - x
     * @param t2d 2d * xy
     */
    CachedXYT(long[] yPlusX, long[] yMinusX, long[] t2d) {
      this.yPlusX = yPlusX;
      this.yMinusX = yMinusX;
      this.t2d = t2d;
    }

    CachedXYT(CachedXYT other) {
      yPlusX = Arrays.copyOf(other.yPlusX, LIMB_CNT);
      yMinusX = Arrays.copyOf(other.yMinusX, LIMB_CNT);
      t2d = Arrays.copyOf(other.t2d, LIMB_CNT);
    }

    // z is one implicitly, so this just copies {@code in} to {@code output}.
    void multByZ(long[] output, long[] in) {
      System.arraycopy(in, 0, output, 0, LIMB_CNT);
    }

    /**
     * If icopy is 1, copies {@code other} into this point. Time invariant wrt to icopy value.
     */
    void copyConditional(CachedXYT other, int icopy) {
      Curve25519.copyConditional(yPlusX, other.yPlusX, icopy);
      Curve25519.copyConditional(yMinusX, other.yMinusX, icopy);
      Curve25519.copyConditional(t2d, other.t2d, icopy);
    }
  }

  private static class CachedXYZT extends CachedXYT {

    private final long[] z;

    CachedXYZT() {
      this(new long[LIMB_CNT], new long[LIMB_CNT], new long[LIMB_CNT], new long[LIMB_CNT]);
    }

    /**
     * ge_p3_to_cached.c
     */
    CachedXYZT(XYZT xyzt) {
      this();
      Field25519.sum(yPlusX, xyzt.xyz.y, xyzt.xyz.x);
      Field25519.sub(yMinusX, xyzt.xyz.y, xyzt.xyz.x);
      System.arraycopy(xyzt.xyz.z, 0, z, 0, LIMB_CNT);
      Field25519.mult(t2d, xyzt.t, D2);
    }

    /**
     * Creates a cached XYZT
     *
     * @param yPlusX Y + X
     * @param yMinusX Y - X
     * @param z Z
     * @param t2d 2d * (XY/Z)
     */
    CachedXYZT(long[] yPlusX, long[] yMinusX, long[] z, long[] t2d) {
      super(yPlusX, yMinusX, t2d);
      this.z = z;
    }

    @Override
    public void multByZ(long[] output, long[] in) {
      Field25519.mult(output, in, z);
    }
  }

  /**
   * Addition defined in Section 3.1 of
   * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
   *
   * Please note that this is a partial of the operation listed there leaving out the final
   * conversion from PartialXYZT to XYZT.
   *
   * @param extended extended projective point input
   * @param cached cached projective point input
   */
  private static void add(PartialXYZT partialXYZT, XYZT extended, CachedXYT cached) {
    long[] t = new long[LIMB_CNT];

    // Y1 + X1
    Field25519.sum(partialXYZT.xyz.x, extended.xyz.y, extended.xyz.x);

    // Y1 - X1
    Field25519.sub(partialXYZT.xyz.y, extended.xyz.y, extended.xyz.x);

    // A = (Y1 - X1) * (Y2 - X2)
    Field25519.mult(partialXYZT.xyz.y, partialXYZT.xyz.y, cached.yMinusX);

    // B = (Y1 + X1) * (Y2 + X2)
    Field25519.mult(partialXYZT.xyz.z, partialXYZT.xyz.x, cached.yPlusX);

    // C = T1 * 2d * T2 = 2d * T1 * T2 (2d is written as k in the paper)
    Field25519.mult(partialXYZT.t, extended.t, cached.t2d);

    // Z1 * Z2
    cached.multByZ(partialXYZT.xyz.x, extended.xyz.z);

    // D = 2 * Z1 * Z2
    Field25519.sum(t, partialXYZT.xyz.x, partialXYZT.xyz.x);

    // X3 = B - A
    Field25519.sub(partialXYZT.xyz.x, partialXYZT.xyz.z, partialXYZT.xyz.y);

    // Y3 = B + A
    Field25519.sum(partialXYZT.xyz.y, partialXYZT.xyz.z, partialXYZT.xyz.y);

    // Z3 = D + C
    Field25519.sum(partialXYZT.xyz.z, t, partialXYZT.t);

    // T3 = D - C
    Field25519.sub(partialXYZT.t, t, partialXYZT.t);
  }

  /**
   * Based on the addition defined in Section 3.1 of
   * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
   *
   * Please note that this is a partial of the operation listed there leaving out the final
   * conversion from PartialXYZT to XYZT.
   *
   * @param extended extended projective point input
   * @param cached cached projective point input
   */
  private static void sub(PartialXYZT partialXYZT, XYZT extended, CachedXYT cached) {
    long[] t = new long[LIMB_CNT];

    // Y1 + X1
    Field25519.sum(partialXYZT.xyz.x, extended.xyz.y, extended.xyz.x);

    // Y1 - X1
    Field25519.sub(partialXYZT.xyz.y, extended.xyz.y, extended.xyz.x);

    // A = (Y1 - X1) * (Y2 + X2)
    Field25519.mult(partialXYZT.xyz.y, partialXYZT.xyz.y, cached.yPlusX);

    // B = (Y1 + X1) * (Y2 - X2)
    Field25519.mult(partialXYZT.xyz.z, partialXYZT.xyz.x, cached.yMinusX);

    // C = T1 * 2d * T2 = 2d * T1 * T2 (2d is written as k in the paper)
    Field25519.mult(partialXYZT.t, extended.t, cached.t2d);

    // Z1 * Z2
    cached.multByZ(partialXYZT.xyz.x, extended.xyz.z);

    // D = 2 * Z1 * Z2
    Field25519.sum(t, partialXYZT.xyz.x, partialXYZT.xyz.x);

    // X3 = B - A
    Field25519.sub(partialXYZT.xyz.x, partialXYZT.xyz.z, partialXYZT.xyz.y);

    // Y3 = B + A
    Field25519.sum(partialXYZT.xyz.y, partialXYZT.xyz.z, partialXYZT.xyz.y);

    // Z3 = D - C
    Field25519.sub(partialXYZT.xyz.z, t, partialXYZT.t);

    // T3 = D + C
    Field25519.sum(partialXYZT.t, t, partialXYZT.t);
  }

  /**
   * Doubles {@code p} and puts the result into this PartialXYZT.
   *
   * This is based on the addition defined in formula 7 in Section 3.3 of
   * Hisil H., Wong K.KH., Carter G., Dawson E. (2008) Twisted Edwards Curves Revisited.
   *
   * Please note that this is a partial of the operation listed there leaving out the final
   * conversion from PartialXYZT to XYZT and also this fixes a typo in calculation of Y3 and T3 in
   * the paper, H should be replaced with A+B.
   */
  private static void doubleXYZ(PartialXYZT partialXYZT, XYZ p) {
    long[] t0 = new long[LIMB_CNT];

    // XX = X1^2
    Field25519.square(partialXYZT.xyz.x, p.x);

    // YY = Y1^2
    Field25519.square(partialXYZT.xyz.z, p.y);

    // B' = Z1^2
    Field25519.square(partialXYZT.t, p.z);

    // B = 2 * B'
    Field25519.sum(partialXYZT.t, partialXYZT.t, partialXYZT.t);

    // A = X1 + Y1
    Field25519.sum(partialXYZT.xyz.y, p.x, p.y);

    // AA = A^2
    Field25519.square(t0, partialXYZT.xyz.y);

    // Y3 = YY + XX
    Field25519.sum(partialXYZT.xyz.y, partialXYZT.xyz.z, partialXYZT.xyz.x);

    // Z3 = YY - XX
    Field25519.sub(partialXYZT.xyz.z, partialXYZT.xyz.z, partialXYZT.xyz.x);

    // X3 = AA - Y3
    Field25519.sub(partialXYZT.xyz.x, t0, partialXYZT.xyz.y);

    // T3 = B - Z3
    Field25519.sub(partialXYZT.t, partialXYZT.t, partialXYZT.xyz.z);
  }

  /**
   * Doubles {@code p} and puts the result into this PartialXYZT.
   */
  private static void doubleXYZT(PartialXYZT partialXYZT, XYZT p) {
    doubleXYZ(partialXYZT, p.xyz);
  }

  /**
   * Compares two byte values in constant time.
   *
   * Please note that this doesn't reuse {@link Curve25519#eq} method since the below inputs are
   * byte values.
   */
  private static int eq(int a, int b) {
    int r = ~(a ^ b) & 0xff;
    r &= r << 4;
    r &= r << 2;
    r &= r << 1;
    return (r >> 7) & 1;
  }

  /**
   * This is a constant time operation where point b*B*256^pos is stored in {@code t}.
   * When b is 0, t remains the same (i.e., neutral point).
   *
   * Although B_TABLE[32][8] (B_TABLE[i][j] = (j+1)*B*256^i) has j values in [0, 7], the select
   * method negates the corresponding point if b is negative (which is straight forward in elliptic
   * curves by just negating y coordinate). Therefore we can get multiples of B with the half of
   * memory requirements.
   *
   * @param t neutral element (i.e., point 0), also serves as output.
   * @param pos in B[pos][j] = (j+1)*B*256^pos
   * @param b value in [-8, 8] range.
   */
  private static void select(CachedXYT t, int pos, byte b) {
    int bnegative = (b & 0xff) >> 7;
    int babs = b - (((-bnegative) & b) << 1);

    t.copyConditional(B_TABLE[pos][0], eq(babs, 1));
    t.copyConditional(B_TABLE[pos][1], eq(babs, 2));
    t.copyConditional(B_TABLE[pos][2], eq(babs, 3));
    t.copyConditional(B_TABLE[pos][3], eq(babs, 4));
    t.copyConditional(B_TABLE[pos][4], eq(babs, 5));
    t.copyConditional(B_TABLE[pos][5], eq(babs, 6));
    t.copyConditional(B_TABLE[pos][6], eq(babs, 7));
    t.copyConditional(B_TABLE[pos][7], eq(babs, 8));

    long[] yPlusX = Arrays.copyOf(t.yMinusX, LIMB_CNT);
    long[] yMinusX = Arrays.copyOf(t.yPlusX, LIMB_CNT);
    long[] t2d = Arrays.copyOf(t.t2d, LIMB_CNT);
    neg(t2d, t2d);
    CachedXYT minust = new CachedXYT(yPlusX, yMinusX, t2d);
    t.copyConditional(minust, bnegative);
  }

  /**
   * Computes {@code a}*B
   * where a = a[0]+256*a[1]+...+256^31 a[31] and
   * B is the Ed25519 base point (x,4/5) with x positive.
   *
   * Preconditions:
   * a[31] <= 127
   * @throws IllegalStateException iff there is arithmetic error.
   */
  @SuppressWarnings("NarrowingCompoundAssignment")
  private static XYZ scalarMultWithBase(byte[] a) {
    byte[] e = new byte[2 * FIELD_LEN];
    for (int i = 0; i < FIELD_LEN; i++) {
      e[2 * i + 0] = (byte) (((a[i] & 0xff) >> 0) & 0xf);
      e[2 * i + 1] = (byte) (((a[i] & 0xff) >> 4) & 0xf);
    }
    // each e[i] is between 0 and 15
    // e[63] is between 0 and 7

    // Rewrite e in a way that each e[i] is in [-8, 8].
    // This can be done since a[63] is in [0, 7], the carry-over onto the most significant byte
    // a[63] can be at most 1.
    int carry = 0;
    for (int i = 0; i < e.length - 1; i++) {
      e[i] += carry;
      carry = e[i] + 8;
      carry >>= 4;
      e[i] -= carry << 4;
    }
    e[e.length - 1] += carry;

    PartialXYZT ret = new PartialXYZT(NEUTRAL);
    XYZT xyzt = new XYZT();
    // Although B_TABLE's i can be at most 31 (stores only 32 4bit multiples of B) and we have 64
    // 4bit values in e array, the below for loop adds cached values by iterating e by two in odd
    // indices. After the result, we can double the result point 4 times to shift the multiplication
    // scalar by 4 bits.
    for (int i = 1; i < e.length; i += 2) {
      CachedXYT t = new CachedXYT(CACHED_NEUTRAL);
      select(t, i / 2, e[i]);
      add(ret, XYZT.fromPartialXYZT(xyzt, ret), t);
    }

    // Doubles the result 4 times to shift the multiplication scalar 4 bits to get the actual result
    // for the odd indices in e.
    XYZ xyz = new XYZ();
    doubleXYZ(ret, XYZ.fromPartialXYZT(xyz, ret));
    doubleXYZ(ret, XYZ.fromPartialXYZT(xyz, ret));
    doubleXYZ(ret, XYZ.fromPartialXYZT(xyz, ret));
    doubleXYZ(ret, XYZ.fromPartialXYZT(xyz, ret));

    // Add multiples of B for even indices of e.
    for (int i = 0; i < e.length; i += 2) {
      CachedXYT t = new CachedXYT(CACHED_NEUTRAL);
      select(t, i / 2, e[i]);
      add(ret, XYZT.fromPartialXYZT(xyzt, ret), t);
    }

    // This check is to protect against flaws, i.e. if there is a computation error through a
    // faulty CPU or if the implementation contains a bug.
    XYZ result = new XYZ(ret);
    if (!result.isOnCurve()) {
      throw new IllegalStateException("arithmetic error in scalar multiplication");
    }
    return result;
  }

  /**
   * Computes {@code a}*B
   * where a = a[0]+256*a[1]+...+256^31 a[31] and
   * B is the Ed25519 base point (x,4/5) with x positive.
   *
   * Preconditions:
   * a[31] <= 127
   */
  static byte[] scalarMultWithBaseToBytes(byte[] a) {
    return scalarMultWithBase(a).toBytes();
  }

  @SuppressWarnings("NarrowingCompoundAssignment")
  private static byte[] slide(byte[] a) {
    byte[] r = new byte[256];
    // Writes each bit in a[0..31] into r[0..255]:
    // a = a[0]+256*a[1]+...+256^31*a[31] is equal to
    // r = r[0]+2*r[1]+...+2^255*r[255]
    for (int i = 0; i < 256; i++) {
      r[i] = (byte) (1 & ((a[i >> 3] & 0xff) >> (i & 7)));
    }

    // Transforms r[i] as odd values in [-15, 15]
    for (int i = 0; i < 256; i++) {
      if (r[i] != 0) {
        for (int b = 1; b <= 6 && i + b < 256; b++) {
          if (r[i + b] != 0) {
            if (r[i] + (r[i + b] << b) <= 15) {
              r[i] += r[i + b] << b;
              r[i + b] = 0;
            } else if (r[i] - (r[i + b] << b) >= -15) {
              r[i] -= r[i + b] << b;
              for (int k = i + b; k < 256; k++) {
                if (r[k] == 0) {
                  r[k] = 1;
                  break;
                }
                r[k] = 0;
              }
            } else {
              break;
            }
          }
        }
      }
    }
    return r;
  }

  /**
   * Computes {@code a}*{@code pointA}+{@code b}*B
   * where a = a[0]+256*a[1]+...+256^31*a[31].
   * and b = b[0]+256*b[1]+...+256^31*b[31].
   * B is the Ed25519 base point (x,4/5) with x positive.
   *
   * Note that execution time varies based on the input since this will only be used in verification
   * of signatures.
   */
  private static XYZ doubleScalarMultVarTime(byte[] a, XYZT pointA, byte[] b) {
    // pointA, 3*pointA, 5*pointA, 7*pointA, 9*pointA, 11*pointA, 13*pointA, 15*pointA
    CachedXYZT[] pointAArray = new CachedXYZT[8];
    pointAArray[0] = new CachedXYZT(pointA);
    PartialXYZT t = new PartialXYZT();
    doubleXYZT(t, pointA);
    XYZT doubleA = new XYZT(t);
    for (int i = 1; i < pointAArray.length; i++) {
      add(t, doubleA, pointAArray[i - 1]);
      pointAArray[i] = new CachedXYZT(new XYZT(t));
    }

    byte[] aSlide = slide(a);
    byte[] bSlide = slide(b);
    t = new PartialXYZT(NEUTRAL);
    XYZT u = new XYZT();
    int i = 255;
    for (; i >= 0; i--) {
      if (aSlide[i] != 0 || bSlide[i] != 0) {
        break;
      }
    }
    for (; i >= 0; i--) {
      doubleXYZ(t, new XYZ(t));
      if (aSlide[i] > 0) {
        add(t, XYZT.fromPartialXYZT(u, t), pointAArray[aSlide[i] / 2]);
      } else if (aSlide[i] < 0) {
        sub(t, XYZT.fromPartialXYZT(u, t), pointAArray[-aSlide[i] / 2]);
      }
      if (bSlide[i] > 0) {
        add(t, XYZT.fromPartialXYZT(u, t), B2[bSlide[i] / 2]);
      } else if (bSlide[i] < 0) {
        sub(t, XYZT.fromPartialXYZT(u, t), B2[-bSlide[i] / 2]);
      }
    }

    return new XYZ(t);
  }

  /**
   * Returns true if {@code in} is nonzero.
   *
   * Note that execution time might depend on the input {@code in}.
   */
  private static boolean isNonZeroVarTime(long[] in) {
    long[] inCopy = new long[in.length + 1];
    System.arraycopy(in, 0, inCopy, 0, in.length);
    Field25519.reduceCoefficients(inCopy);
    byte[] bytes = Field25519.contract(inCopy);
    for (byte b : bytes) {
      if (b != 0) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns the least significant bit of {@code in}.
   */
  private static int getLsb(long[] in) {
    return Field25519.contract(in)[0] & 1;
  }

  /**
   * Negates all values in {@code in} and store it in {@code out}.
   */
  private static void neg(long[] out, long[] in) {
    for (int i = 0; i < in.length; i++) {
      out[i] = -in[i];
    }
  }

  /**
   * Computes {@code in}^(2^252-3) mod 2^255-19 and puts the result in {@code out}.
   */
  private static void pow2252m3(long[] out, long[] in) {
    long[] t0 = new long[LIMB_CNT];
    long[] t1 = new long[LIMB_CNT];
    long[] t2 = new long[LIMB_CNT];

    // z2 = z1^2^1
    Field25519.square(t0, in);

    // z8 = z2^2^2
    Field25519.square(t1, t0);
    for (int i = 1; i < 2; i++) {
      Field25519.square(t1, t1);
    }

    // z9 = z1*z8
    Field25519.mult(t1, in, t1);

    // z11 = z2*z9
    Field25519.mult(t0, t0, t1);

    // z22 = z11^2^1
    Field25519.square(t0, t0);

    // z_5_0 = z9*z22
    Field25519.mult(t0, t1, t0);

    // z_10_5 = z_5_0^2^5
    Field25519.square(t1, t0);
    for (int i = 1; i < 5; i++) {
      Field25519.square(t1, t1);
    }

    // z_10_0 = z_10_5*z_5_0
    Field25519.mult(t0, t1, t0);

    // z_20_10 = z_10_0^2^10
    Field25519.square(t1, t0);
    for (int i = 1; i < 10; i++) {
      Field25519.square(t1, t1);
    }

    // z_20_0 = z_20_10*z_10_0
    Field25519.mult(t1, t1, t0);

    // z_40_20 = z_20_0^2^20
    Field25519.square(t2, t1);
    for (int i = 1; i < 20; i++) {
      Field25519.square(t2, t2);
    }

    // z_40_0 = z_40_20*z_20_0
    Field25519.mult(t1, t2, t1);

    // z_50_10 = z_40_0^2^10
    Field25519.square(t1, t1);
    for (int i = 1; i < 10; i++) {
      Field25519.square(t1, t1);
    }

    // z_50_0 = z_50_10*z_10_0
    Field25519.mult(t0, t1, t0);

    // z_100_50 = z_50_0^2^50
    Field25519.square(t1, t0);
    for (int i = 1; i < 50; i++) {
      Field25519.square(t1, t1);
    }

    // z_100_0 = z_100_50*z_50_0
    Field25519.mult(t1, t1, t0);

    // z_200_100 = z_100_0^2^100
    Field25519.square(t2, t1);
    for (int i = 1; i < 100; i++) {
      Field25519.square(t2, t2);
    }

    // z_200_0 = z_200_100*z_100_0
    Field25519.mult(t1, t2, t1);

    // z_250_50 = z_200_0^2^50
    Field25519.square(t1, t1);
    for (int i = 1; i < 50; i++) {
      Field25519.square(t1, t1);
    }

    // z_250_0 = z_250_50*z_50_0
    Field25519.mult(t0, t1, t0);

    // z_252_2 = z_250_0^2^2
    Field25519.square(t0, t0);
    for (int i = 1; i < 2; i++) {
      Field25519.square(t0, t0);
    }

    // z_252_3 = z_252_2*z1
    Field25519.mult(out, t0, in);
  }

  /**
   * Returns 3 bytes of {@code in} starting from {@code idx} in Little-Endian format.
   */
  private static long load3(byte[] in, int idx) {
    long result;
    result = (long) in[idx] & 0xff;
    result |= (long) (in[idx + 1] & 0xff) << 8;
    result |= (long) (in[idx + 2] & 0xff) << 16;
    return result;
  }

  /**
   * Returns 4 bytes of {@code in} starting from {@code idx} in Little-Endian format.
   */
  private static long load4(byte[] in, int idx) {
    long result = load3(in, idx);
    result |= (long) (in[idx + 3] & 0xff) << 24;
    return result;
  }

  /**
   * Input:
   * s[0]+256*s[1]+...+256^63*s[63] = s
   *
   * Output:
   * s[0]+256*s[1]+...+256^31*s[31] = s mod l
   * where l = 2^252 + 27742317777372353535851937790883648493.
   * Overwrites s in place.
   */
  private static void reduce(byte[] s) {
    // Observation:
    // 2^252 mod l is equivalent to -27742317777372353535851937790883648493 mod l
    // Let m = -27742317777372353535851937790883648493
    // Thus a*2^252+b mod l is equivalent to a*m+b mod l
    //
    // First s is divided into chunks of 21 bits as follows:
    // s0+2^21*s1+2^42*s3+...+2^462*s23 = s[0]+256*s[1]+...+256^63*s[63]
    long s0 = 2097151 & load3(s, 0);
    long s1 = 2097151 & (load4(s, 2) >> 5);
    long s2 = 2097151 & (load3(s, 5) >> 2);
    long s3 = 2097151 & (load4(s, 7) >> 7);
    long s4 = 2097151 & (load4(s, 10) >> 4);
    long s5 = 2097151 & (load3(s, 13) >> 1);
    long s6 = 2097151 & (load4(s, 15) >> 6);
    long s7 = 2097151 & (load3(s, 18) >> 3);
    long s8 = 2097151 & load3(s, 21);
    long s9 = 2097151 & (load4(s, 23) >> 5);
    long s10 = 2097151 & (load3(s, 26) >> 2);
    long s11 = 2097151 & (load4(s, 28) >> 7);
    long s12 = 2097151 & (load4(s, 31) >> 4);
    long s13 = 2097151 & (load3(s, 34) >> 1);
    long s14 = 2097151 & (load4(s, 36) >> 6);
    long s15 = 2097151 & (load3(s, 39) >> 3);
    long s16 = 2097151 & load3(s, 42);
    long s17 = 2097151 & (load4(s, 44) >> 5);
    long s18 = 2097151 & (load3(s, 47) >> 2);
    long s19 = 2097151 & (load4(s, 49) >> 7);
    long s20 = 2097151 & (load4(s, 52) >> 4);
    long s21 = 2097151 & (load3(s, 55) >> 1);
    long s22 = 2097151 & (load4(s, 57) >> 6);
    long s23 = (load4(s, 60) >> 3);
    long carry0;
    long carry1;
    long carry2;
    long carry3;
    long carry4;
    long carry5;
    long carry6;
    long carry7;
    long carry8;
    long carry9;
    long carry10;
    long carry11;
    long carry12;
    long carry13;
    long carry14;
    long carry15;
    long carry16;

    // s23*2^462 = s23*2^210*2^252 is equivalent to s23*2^210*m in mod l
    // As m is a 125 bit number, the result needs to scattered to 6 limbs (125/21 ceil is 6)
    // starting from s11 (s11*2^210)
    // m = [666643, 470296, 654183, -997805, 136657, -683901] in 21-bit limbs
    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    // s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    // s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    // s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    // s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    // s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    // s18 = 0;

    // Reduce the bit length of limbs from s6 to s15 to 21-bits.
    carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

    carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

    // Resume reduction where we left off.
    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    // s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    // s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    // s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    // s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    // s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    // Reduce the range of limbs from s0 to s11 to 21-bits.
    carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

    carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    // Carry chain reduction to propagate excess bits from s0 to s5 to the most significant limbs.
    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

    // Do one last reduction as s12 might be 1.
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    // s12 = 0;

    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

    // Serialize the result into the s.
    s[0] = (byte) s0;
    s[1] = (byte) (s0 >> 8);
    s[2] = (byte) ((s0 >> 16) | (s1 << 5));
    s[3] = (byte) (s1 >> 3);
    s[4] = (byte) (s1 >> 11);
    s[5] = (byte) ((s1 >> 19) | (s2 << 2));
    s[6] = (byte) (s2 >> 6);
    s[7] = (byte) ((s2 >> 14) | (s3 << 7));
    s[8] = (byte) (s3 >> 1);
    s[9] = (byte) (s3 >> 9);
    s[10] = (byte) ((s3 >> 17) | (s4 << 4));
    s[11] = (byte) (s4 >> 4);
    s[12] = (byte) (s4 >> 12);
    s[13] = (byte) ((s4 >> 20) | (s5 << 1));
    s[14] = (byte) (s5 >> 7);
    s[15] = (byte) ((s5 >> 15) | (s6 << 6));
    s[16] = (byte) (s6 >> 2);
    s[17] = (byte) (s6 >> 10);
    s[18] = (byte) ((s6 >> 18) | (s7 << 3));
    s[19] = (byte) (s7 >> 5);
    s[20] = (byte) (s7 >> 13);
    s[21] = (byte) s8;
    s[22] = (byte) (s8 >> 8);
    s[23] = (byte) ((s8 >> 16) | (s9 << 5));
    s[24] = (byte) (s9 >> 3);
    s[25] = (byte) (s9 >> 11);
    s[26] = (byte) ((s9 >> 19) | (s10 << 2));
    s[27] = (byte) (s10 >> 6);
    s[28] = (byte) ((s10 >> 14) | (s11 << 7));
    s[29] = (byte) (s11 >> 1);
    s[30] = (byte) (s11 >> 9);
    s[31] = (byte) (s11 >> 17);
  }

  /**
   * Input:
   * a[0]+256*a[1]+...+256^31*a[31] = a
   * b[0]+256*b[1]+...+256^31*b[31] = b
   * c[0]+256*c[1]+...+256^31*c[31] = c
   *
   * Output:
   * s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
   * where l = 2^252 + 27742317777372353535851937790883648493.
   */
  private static void mulAdd(byte[] s, byte[] a, byte[] b, byte[] c) {
    // This is very similar to Ed25519.reduce, the difference in here is that it computes ab+c
    // See Ed25519.reduce for related comments.
    long a0 = 2097151 & load3(a, 0);
    long a1 = 2097151 & (load4(a, 2) >> 5);
    long a2 = 2097151 & (load3(a, 5) >> 2);
    long a3 = 2097151 & (load4(a, 7) >> 7);
    long a4 = 2097151 & (load4(a, 10) >> 4);
    long a5 = 2097151 & (load3(a, 13) >> 1);
    long a6 = 2097151 & (load4(a, 15) >> 6);
    long a7 = 2097151 & (load3(a, 18) >> 3);
    long a8 = 2097151 & load3(a, 21);
    long a9 = 2097151 & (load4(a, 23) >> 5);
    long a10 = 2097151 & (load3(a, 26) >> 2);
    long a11 = (load4(a, 28) >> 7);
    long b0 = 2097151 & load3(b, 0);
    long b1 = 2097151 & (load4(b, 2) >> 5);
    long b2 = 2097151 & (load3(b, 5) >> 2);
    long b3 = 2097151 & (load4(b, 7) >> 7);
    long b4 = 2097151 & (load4(b, 10) >> 4);
    long b5 = 2097151 & (load3(b, 13) >> 1);
    long b6 = 2097151 & (load4(b, 15) >> 6);
    long b7 = 2097151 & (load3(b, 18) >> 3);
    long b8 = 2097151 & load3(b, 21);
    long b9 = 2097151 & (load4(b, 23) >> 5);
    long b10 = 2097151 & (load3(b, 26) >> 2);
    long b11 = (load4(b, 28) >> 7);
    long c0 = 2097151 & load3(c, 0);
    long c1 = 2097151 & (load4(c, 2) >> 5);
    long c2 = 2097151 & (load3(c, 5) >> 2);
    long c3 = 2097151 & (load4(c, 7) >> 7);
    long c4 = 2097151 & (load4(c, 10) >> 4);
    long c5 = 2097151 & (load3(c, 13) >> 1);
    long c6 = 2097151 & (load4(c, 15) >> 6);
    long c7 = 2097151 & (load3(c, 18) >> 3);
    long c8 = 2097151 & load3(c, 21);
    long c9 = 2097151 & (load4(c, 23) >> 5);
    long c10 = 2097151 & (load3(c, 26) >> 2);
    long c11 = (load4(c, 28) >> 7);
    long s0;
    long s1;
    long s2;
    long s3;
    long s4;
    long s5;
    long s6;
    long s7;
    long s8;
    long s9;
    long s10;
    long s11;
    long s12;
    long s13;
    long s14;
    long s15;
    long s16;
    long s17;
    long s18;
    long s19;
    long s20;
    long s21;
    long s22;
    long s23;
    long carry0;
    long carry1;
    long carry2;
    long carry3;
    long carry4;
    long carry5;
    long carry6;
    long carry7;
    long carry8;
    long carry9;
    long carry10;
    long carry11;
    long carry12;
    long carry13;
    long carry14;
    long carry15;
    long carry16;
    long carry17;
    long carry18;
    long carry19;
    long carry20;
    long carry21;
    long carry22;

    s0 = c0 + a0 * b0;
    s1 = c1 + a0 * b1 + a1 * b0;
    s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1
        + a8 * b0;
    s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2
        + a8 * b1 + a9 * b0;
    s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3
        + a8 * b2 + a9 * b1 + a10 * b0;
    s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4
        + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
    s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3
        + a10 * b2 + a11 * b1;
    s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3
        + a11 * b2;
    s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4
        + a11 * b3;
    s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s20 = a9 * b11 + a10 * b10 + a11 * b9;
    s21 = a10 * b11 + a11 * b10;
    s22 = a11 * b11;
    s23 = 0;

    carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
    carry18 = (s18 + (1 << 20)) >> 21; s19 += carry18; s18 -= carry18 << 21;
    carry20 = (s20 + (1 << 20)) >> 21; s21 += carry20; s20 -= carry20 << 21;
    carry22 = (s22 + (1 << 20)) >> 21; s23 += carry22; s22 -= carry22 << 21;

    carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;
    carry17 = (s17 + (1 << 20)) >> 21; s18 += carry17; s17 -= carry17 << 21;
    carry19 = (s19 + (1 << 20)) >> 21; s20 += carry19; s19 -= carry19 << 21;
    carry21 = (s21 + (1 << 20)) >> 21; s22 += carry21; s21 -= carry21 << 21;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    // s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    // s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    // s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    // s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    // s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    // s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

    carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    // s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    // s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    // s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    // s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    // s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

    carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    // s12 = 0;

    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

    s[0] = (byte) s0;
    s[1] = (byte) (s0 >> 8);
    s[2] = (byte) ((s0 >> 16) | (s1 << 5));
    s[3] = (byte) (s1 >> 3);
    s[4] = (byte) (s1 >> 11);
    s[5] = (byte) ((s1 >> 19) | (s2 << 2));
    s[6] = (byte) (s2 >> 6);
    s[7] = (byte) ((s2 >> 14) | (s3 << 7));
    s[8] = (byte) (s3 >> 1);
    s[9] = (byte) (s3 >> 9);
    s[10] = (byte) ((s3 >> 17) | (s4 << 4));
    s[11] = (byte) (s4 >> 4);
    s[12] = (byte) (s4 >> 12);
    s[13] = (byte) ((s4 >> 20) | (s5 << 1));
    s[14] = (byte) (s5 >> 7);
    s[15] = (byte) ((s5 >> 15) | (s6 << 6));
    s[16] = (byte) (s6 >> 2);
    s[17] = (byte) (s6 >> 10);
    s[18] = (byte) ((s6 >> 18) | (s7 << 3));
    s[19] = (byte) (s7 >> 5);
    s[20] = (byte) (s7 >> 13);
    s[21] = (byte) s8;
    s[22] = (byte) (s8 >> 8);
    s[23] = (byte) ((s8 >> 16) | (s9 << 5));
    s[24] = (byte) (s9 >> 3);
    s[25] = (byte) (s9 >> 11);
    s[26] = (byte) ((s9 >> 19) | (s10 << 2));
    s[27] = (byte) (s10 >> 6);
    s[28] = (byte) ((s10 >> 14) | (s11 << 7));
    s[29] = (byte) (s11 >> 1);
    s[30] = (byte) (s11 >> 9);
    s[31] = (byte) (s11 >> 17);
  }

  static byte[] getHashedScalar(final byte[] privateKey)
      throws GeneralSecurityException {
    MessageDigest digest = EngineFactory.MESSAGE_DIGEST.getInstance("SHA-512");
    digest.update(privateKey, 0, FIELD_LEN);
    byte[] h = digest.digest();
    // https://tools.ietf.org/html/rfc8032#section-5.1.2.
    // Clear the lowest three bits of the first octet.
    h[0] = (byte) (h[0] & 248);
    // Clear the highest bit of the last octet.
    h[31] = (byte) (h[31] & 127);
    // Set the second highest bit if the last octet.
    h[31] = (byte) (h[31] | 64);
    return h;
  }

  /**
   * Returns the EdDSA signature for the {@code message} based on the {@code hashedPrivateKey}.
   *
   * @param message to sign
   * @param publicKey {@link Ed25519#scalarMultToBytes(byte[])} of {@code hashedPrivateKey}
   * @param hashedPrivateKey {@link Ed25519#getHashedScalar(byte[])} of the private key
   * @return signature for the {@code message}.
   * @throws GeneralSecurityException if there is no SHA-512 algorithm defined in
   * {@link EngineFactory}.MESSAGE_DIGEST.
   */
  static byte[] sign(final byte[] message, final byte[] publicKey, final byte[] hashedPrivateKey)
      throws GeneralSecurityException {
    // Copying the message to make it thread-safe. Otherwise, if the caller modifies the message
    // between the first and the second hash then it might leak the private key.
    byte[] messageCopy = Arrays.copyOfRange(message, 0, message.length);
    MessageDigest digest = EngineFactory.MESSAGE_DIGEST.getInstance("SHA-512");
    digest.update(hashedPrivateKey, FIELD_LEN, FIELD_LEN);
    digest.update(messageCopy);
    byte[] r = digest.digest();
    reduce(r);

    byte[] rB = Arrays.copyOfRange(scalarMultWithBase(r).toBytes(), 0, FIELD_LEN);
    digest.reset();
    digest.update(rB);
    digest.update(publicKey);
    digest.update(messageCopy);
    byte[] hram = digest.digest();
    reduce(hram);
    byte[] s = new byte[FIELD_LEN];
    mulAdd(s, hram, hashedPrivateKey, r);
    return Bytes.concat(rB, s);
  }


  // The order of the generator as unsigned bytes in little endian order.
  // (2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed, cf. RFC 7748)
  static final byte[] GROUP_ORDER = new byte[] {
     (byte) 0xed, (byte) 0xd3, (byte) 0xf5, (byte) 0x5c,
     (byte) 0x1a, (byte) 0x63, (byte) 0x12, (byte) 0x58,
     (byte) 0xd6, (byte) 0x9c, (byte) 0xf7, (byte) 0xa2,
     (byte) 0xde, (byte) 0xf9, (byte) 0xde, (byte) 0x14,
     (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
     (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
     (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
     (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x10};

  // Checks whether s represents an integer smaller than the order of the group.
  // This is needed to ensure that EdDSA signatures are non-malleable, as failing to check
  // the range of S allows to modify signatures (cf. RFC 8032, Section 5.2.7 and Section 8.4.)
  // @param s an integer in little-endian order.
  private static boolean isSmallerThanGroupOrder(byte[] s) {
    for (int j = FIELD_LEN - 1; j >= 0; j--) {
      // compare unsigned bytes
      int a = s[j] & 0xff;
      int b = GROUP_ORDER[j] & 0xff;
      if (a != b) {
        return a < b;
      }
    }
    return false;
  }

  /**
   * Returns true if the EdDSA {@code signature} with {@code message}, can be verified with
   * {@code publicKey}.
   *
   * @throws GeneralSecurityException if there is no SHA-512 algorithm defined in
   * {@link EngineFactory}.MESSAGE_DIGEST.
   */
  static boolean verify(final byte[] message, final byte[] signature,
      final byte[] publicKey) throws GeneralSecurityException {
    if (signature.length != SIGNATURE_LEN) {
      return false;
    }
    byte[] s = Arrays.copyOfRange(signature, FIELD_LEN, SIGNATURE_LEN);
    if (!isSmallerThanGroupOrder(s)) {
      return false;
    }
    MessageDigest digest = EngineFactory.MESSAGE_DIGEST.getInstance("SHA-512");
    digest.update(signature, 0, FIELD_LEN);
    digest.update(publicKey);
    digest.update(message);
    byte[] h = digest.digest();
    reduce(h);

    XYZT negPublicKey = XYZT.fromBytesNegateVarTime(publicKey);
    XYZ xyz = doubleScalarMultVarTime(h, negPublicKey, s);
    byte[] expectedR = xyz.toBytes();
    for (int i = 0; i < FIELD_LEN; i++) {
      if (expectedR[i] != signature[i]) {
        return false;
      }
    }
    return true;
  }

  private Ed25519() {}
}
