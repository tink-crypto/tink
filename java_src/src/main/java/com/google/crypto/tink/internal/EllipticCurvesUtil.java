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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * Utility functions for elliptic curve crypto, used in ECDSA and ECDH.
 */
public final class EllipticCurvesUtil {

  public static final ECParameterSpec NIST_P256_PARAMS = getNistP256Params();
  public static final ECParameterSpec NIST_P384_PARAMS = getNistP384Params();
  public static final ECParameterSpec NIST_P521_PARAMS = getNistP521Params();

  private static ECParameterSpec getNistP256Params() {
    return getNistCurveSpec(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951",
        "115792089210356248762697446949407573529996955224135760342422259061068512044369",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
  }

  private static ECParameterSpec getNistP384Params() {
    return getNistCurveSpec(
        "3940200619639447921227904010014361380507973927046544666794829340"
            + "4245721771496870329047266088258938001861606973112319",
        "3940200619639447921227904010014361380507973927046544666794690527"
            + "9627659399113263569398956308152294913554433653942643",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
            + "c656398d8a2ed19d2a85c8edd3ec2aef",
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
            + "5502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
            + "0a60b1ce1d7e819d7a431d7c90ea0e5f");
  }

  private static ECParameterSpec getNistP521Params() {
    return getNistCurveSpec(
        "6864797660130609714981900799081393217269435300143305409394463459"
            + "18554318339765605212255964066145455497729631139148085803712198"
            + "7999716643812574028291115057151",
        "6864797660130609714981900799081393217269435300143305409394463459"
            + "18554318339765539424505774633321719753296399637136332111386476"
            + "8612440380340372808892707005449",
        "051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10"
            + "9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d"
            + "baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6"
            + "62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650");
  }

  /**
   * Checks that a point is on a given elliptic curve.
   *
   * <p>This method implements the partial public key validation routine from Section 5.6.2.6 of <a
   * href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf">NIST SP
   * 800-56A</a>. A partial public key validation is sufficient for curves with cofactor 1. See
   * Section B.3 of http://www.nsa.gov/ia/_files/SuiteB_Implementer_G-113808.pdf.
   *
   * <p>The point validations above are taken from recommendations for ECDH, because parameter
   * checks in ECDH are much more important than for the case of ECDSA. Performing this test for
   * ECDSA keys is mainly a sanity check.
   *
   * @param point the point that needs verification
   * @param ec the elliptic curve. This must be a curve over a prime order field.
   * @throws GeneralSecurityException if the field is binary or if the point is not on the curve.
   */
  public static void checkPointOnCurve(ECPoint point, EllipticCurve ec)
      throws GeneralSecurityException {
    BigInteger p = getModulus(ec);
    BigInteger x = point.getAffineX();
    BigInteger y = point.getAffineY();
    if (x == null || y == null) {
      throw new GeneralSecurityException("point is at infinity");
    }
    // Check 0 <= x < p and 0 <= y < p.
    if (x.signum() == -1 || x.compareTo(p) >= 0) {
      throw new GeneralSecurityException("x is out of range");
    }
    if (y.signum() == -1 || y.compareTo(p) >= 0) {
      throw new GeneralSecurityException("y is out of range");
    }
    // Check y^2 == x^3 + a x + b (mod p)
    BigInteger lhs = y.multiply(y).mod(p);
    BigInteger rhs = x.multiply(x).add(ec.getA()).multiply(x).add(ec.getB()).mod(p);
    if (!lhs.equals(rhs)) {
      throw new GeneralSecurityException("Point is not on curve");
    }
  }


  /** Returns whether {@code spec} is a {@link ECParameterSpec} of one of the NIST curves. */
  public static boolean isNistEcParameterSpec(ECParameterSpec spec) {
    return isSameEcParameterSpec(spec, NIST_P256_PARAMS)
        || isSameEcParameterSpec(spec, NIST_P384_PARAMS)
        || isSameEcParameterSpec(spec, NIST_P521_PARAMS);
  }

  /** Returns whether {@code one} is the same {@link ECParameterSpec} as {@code two}. */
  public static boolean isSameEcParameterSpec(ECParameterSpec one, ECParameterSpec two) {
    return one.getCurve().equals(two.getCurve())
        && one.getGenerator().equals(two.getGenerator())
        && one.getOrder().equals(two.getOrder())
        && one.getCofactor() == two.getCofactor();
  }

  /**
   * Returns the modulus of the field used by the curve specified in ecParams.
   *
   * @param curve must be a prime order elliptic curve
   * @return the order of the finite field over which curve is defined.
   */
  public static BigInteger getModulus(EllipticCurve curve) throws GeneralSecurityException {
    java.security.spec.ECField field = curve.getField();
    if (field instanceof java.security.spec.ECFieldFp) {
      return ((java.security.spec.ECFieldFp) field).getP();
    } else {
      throw new GeneralSecurityException("Only curves over prime order fields are supported");
    }
  }

  private static ECParameterSpec getNistCurveSpec(
      String decimalP, String decimalN, String hexB, String hexGX, String hexGY) {
    final BigInteger p = new BigInteger(decimalP);
    final BigInteger n = new BigInteger(decimalN);
    final BigInteger three = new BigInteger("3");
    final BigInteger a = p.subtract(three);
    final BigInteger b = new BigInteger(hexB, 16);
    final BigInteger gx = new BigInteger(hexGX, 16);
    final BigInteger gy = new BigInteger(hexGY, 16);
    final int h = 1;
    ECFieldFp fp = new ECFieldFp(p);
    java.security.spec.EllipticCurve curveSpec = new java.security.spec.EllipticCurve(fp, a, b);
    ECPoint g = new ECPoint(gx, gy);
    ECParameterSpec ecSpec = new ECParameterSpec(curveSpec, g, n, h);
    return ecSpec;
  }

  private EllipticCurvesUtil() {
  }
}
