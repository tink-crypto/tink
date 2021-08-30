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
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/**
 * Utility functions and enums for elliptic curve crypto, used in ECDSA and ECDH.
 *
 * @since 1.0.0
 */
public final class EllipticCurves {

  /** Point formats. */
  public enum PointFormatType {
    UNCOMPRESSED,
    COMPRESSED,
    // Like UNCOMPRESSED but without the \x04 prefix. Crunchy uses this format.
    // DO NOT USE unless you are a Crunchy user moving to Tink.
    DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
  }

  /** Elliptic curve types. */
  public enum CurveType {
    NIST_P256,
    NIST_P384,
    NIST_P521,
  }

  /** Ecdsa signature encoding. */
  public enum EcdsaEncoding {
    IEEE_P1363,
    DER,
  }

  public static ECParameterSpec getNistP256Params() {
    return getNistCurveSpec(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951",
        "115792089210356248762697446949407573529996955224135760342422259061068512044369",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
  }

  public static ECParameterSpec getNistP384Params() {
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

  public static ECParameterSpec getNistP521Params() {
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
   * <p><b>Warning:</b> Please use {@link #validatePublicKey} if you want to validate a public key
   * to avoid invalid curve attacks or small subgroup attacks in ECDH.
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
  static void checkPointOnCurve(ECPoint point, EllipticCurve ec) throws GeneralSecurityException {
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

  /**
   * Checks that the point of the public key is on the curve of the public key.
   *
   * <h3>Warning</h3>
   *
   * <p>Please use {@link #validatePublicKey} if you want to validate a public key to avoid invalid
   * curve attacks or small subgroup attacks in ECDH.
   *
   * <p>This is a sanity check, because the curve of the public key might be under control of the
   * adversary.
   *
   * @param key must be a key defined over a curve using a prime order field.
   * @throws GeneralSecurityException if the key is not valid.
   */
  static void checkPublicKey(ECPublicKey key) throws GeneralSecurityException {
    checkPointOnCurve(key.getW(), key.getParams().getCurve());
  }

  /** Returns whether {@code spec} is a {@link ECParameterSpec} of one of the NIST curves. */
  public static boolean isNistEcParameterSpec(ECParameterSpec spec) {
    return isSameEcParameterSpec(spec, getNistP256Params())
        || isSameEcParameterSpec(spec, getNistP384Params())
        || isSameEcParameterSpec(spec, getNistP521Params());
  }

  /** Returns whether {@code one} is the same {@link ECParameterSpec} as {@code two}. */
  public static boolean isSameEcParameterSpec(ECParameterSpec one, ECParameterSpec two) {
    return one.getCurve().equals(two.getCurve())
        && one.getGenerator().equals(two.getGenerator())
        && one.getOrder().equals(two.getOrder())
        && one.getCofactor() == two.getCofactor();
  }

  /**
   * Checks that the public key's params is the same as the private key's params, and the public key
   * is a valid point on the private key's curve.
   *
   * @since 1.1.0
   */
  public static void validatePublicKey(ECPublicKey publicKey, ECPrivateKey privateKey)
      throws GeneralSecurityException {
    validatePublicKeySpec(publicKey, privateKey);
    checkPointOnCurve(publicKey.getW(), privateKey.getParams().getCurve());
  }

  /** Checks that the public key's params spec is the same as the private key's params spec. */
  static void validatePublicKeySpec(ECPublicKey publicKey, ECPrivateKey privateKey)
      throws GeneralSecurityException {
    try {
      ECParameterSpec publicKeySpec = publicKey.getParams();
      ECParameterSpec privateKeySpec = privateKey.getParams();
      if (!isSameEcParameterSpec(publicKeySpec, privateKeySpec)) {
        throw new GeneralSecurityException("invalid public key spec");
      }
    } catch (IllegalArgumentException | NullPointerException ex) {
      // The Java security providers on Android K and Android L might throw these unchecked
      // exceptions, converting them to a checked one to not crash the JVM.
      throw new GeneralSecurityException(ex.toString());
    }
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

  /**
   * Returns the size of an element of the field over which the curve is defined.
   *
   * @param curve must be a prime order elliptic curve
   * @return the size of an element in bits
   */
  public static int fieldSizeInBits(EllipticCurve curve) throws GeneralSecurityException {
    return getModulus(curve).subtract(BigInteger.ONE).bitLength();
  }

  /**
   * Returns the size of an element of the field over which the curve is defined.
   *
   * @param curve must be a prime order elliptic curve
   * @return the size of an element in bytes.
   */
  public static int fieldSizeInBytes(EllipticCurve curve) throws GeneralSecurityException {
    return (fieldSizeInBits(curve) + 7) / 8;
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

  /**
   * Computes a square root modulo an odd prime. Timing and exceptions can leak information about
   * the inputs. Therefore this method must only be used to decompress public keys.
   *
   * @param x the square
   * @param p the prime modulus (the behaviour of the method is undefined if p is not prime).
   * @return a value s such that s^2 mod p == x mod p
   * @throws GeneralSecurityException if the square root could not be found.
   */
  protected static BigInteger modSqrt(BigInteger x, BigInteger p) throws GeneralSecurityException {
    if (p.signum() != 1) {
      throw new InvalidAlgorithmParameterException("p must be positive");
    }
    x = x.mod(p);
    BigInteger squareRoot = null;
    // Special case for x == 0.
    // This check is necessary for Cipolla's algorithm.
    if (x.equals(BigInteger.ZERO)) {
      return BigInteger.ZERO;
    }
    if (p.testBit(0) && p.testBit(1)) {
      // Case p % 4 == 3
      // q = (p + 1) / 4
      BigInteger q = p.add(BigInteger.ONE).shiftRight(2);
      squareRoot = x.modPow(q, p);
    } else if (p.testBit(0) && !p.testBit(1)) {
      // Case p % 4 == 1
      // For this case we use Cipolla's algorithm.
      // This alogorithm is preferrable to Tonelli-Shanks for primes p where p-1 is divisible by
      // a large power of 2, which is a frequent choice since it simplifies modular reduction.
      BigInteger a = BigInteger.ONE;
      BigInteger d = null;
      BigInteger q1 = p.subtract(BigInteger.ONE).shiftRight(1);
      int tries = 0;
      while (true) {
        d = a.multiply(a).subtract(x).mod(p);
        // Special case d==0. We need d!=0 below.
        if (d.equals(BigInteger.ZERO)) {
          return a;
        }
        // Computes the Legendre symbol. Using the Jacobi symbol would be a faster.
        BigInteger t = d.modPow(q1, p);
        if (t.add(BigInteger.ONE).equals(p)) {
          // d is a quadratic non-residue.
          break;
        } else if (!t.equals(BigInteger.ONE)) {
          // p does not divide d. Hence, t != 1 implies that p is not a prime.
          throw new InvalidAlgorithmParameterException("p is not prime");
        } else {
          a = a.add(BigInteger.ONE);
        }
        tries++;
        // If 128 tries were not enough to find a quadratic non-residue, then it is likely that
        // p is not prime. To avoid an infinite loop in this case we perform a primality test.
        // If p is prime then this test will be done with a negligible probability of 2^{-128}.
        if (tries == 128) {
          if (!p.isProbablePrime(80)) {
            throw new InvalidAlgorithmParameterException("p is not prime");
          }
        }
      }
      // Since d = a^2 - x is a quadratic non-residue modulo p, we have
      //   a - sqrt(d) == (a + sqrt(d))^p (mod p),
      // and hence
      //   x == (a + sqrt(d))(a - sqrt(d)) == (a + sqrt(d))^(p+1) (mod p).
      // Thus if x is square then (a + sqrt(d))^((p+1)/2) (mod p) is a square root of x.
      BigInteger q = p.add(BigInteger.ONE).shiftRight(1);
      BigInteger u = a;
      BigInteger v = BigInteger.ONE;
      for (int bit = q.bitLength() - 2; bit >= 0; bit--) {
        // Square u + v sqrt(d) and reduce mod p.
        BigInteger tmp = u.multiply(v);
        u = u.multiply(u).add(v.multiply(v).mod(p).multiply(d)).mod(p);
        v = tmp.add(tmp).mod(p);
        if (q.testBit(bit)) {
          // Multiply u + v sqrt(d) by a + sqrt(d) and reduce mod p.
          tmp = u.multiply(a).add(v.multiply(d)).mod(p);
          v = a.multiply(v).add(u).mod(p);
          u = tmp;
        }
      }
      squareRoot = u;
    }
    // The methods used to compute the square root only guarantees a correct result if the
    // preconditions (i.e. p prime and x is a square) are satisfied. Otherwise the value is
    // undefined. Hence it is important to verify that squareRoot is indeed a square root.
    if (squareRoot != null && squareRoot.multiply(squareRoot).mod(p).compareTo(x) != 0) {
      throw new GeneralSecurityException("Could not find a modular square root");
    }
    return squareRoot;
  }

  /**
   * Computes the y coordinate of a point on an elliptic curve. This method can be used to
   * decompress elliptic curve points.
   *
   * @param x the x-coordinate of the point
   * @param lsb the least significant bit of the y-coordinate of the point.
   * @param curve this must be an elliptic curve over a prime field using Weierstrass
   *     representation.
   * @return the y coordinate.
   * @throws GeneralSecurityException if there is no point with coordinate x on the curve, or if
   *     curve is not supported.
   */
  public static BigInteger getY(BigInteger x, boolean lsb, EllipticCurve curve)
      throws GeneralSecurityException {
    BigInteger p = getModulus(curve);
    BigInteger a = curve.getA();
    BigInteger b = curve.getB();
    BigInteger rhs = x.multiply(x).add(a).multiply(x).add(b).mod(p);
    BigInteger y = modSqrt(rhs, p);
    if (lsb != y.testBit(0)) {
      y = p.subtract(y).mod(p);
    }
    return y;
  }

  /**
   * Transforms a big integer to its minimal signed form, i.e., no extra zero byte at the beginning
   * except single one when the highest bit is set.
   */
  private static byte[] toMinimalSignedNumber(byte[] bs) {
    // Remove zero prefixes.
    int start = 0;
    while (start < bs.length && bs[start] == 0) {
      start++;
    }
    if (start == bs.length) {
      start = bs.length - 1;
    }

    int extraZero = 0;
    // If the 1st bit is not zero, add 1 zero byte.
    if ((bs[start] & 0x80) == 0x80) {
      // Add extra zero.
      extraZero = 1;
    }
    byte[] res = new byte[bs.length - start + extraZero];
    System.arraycopy(bs, start, res, extraZero, bs.length - start);
    return res;
  }

  /**
   * Transforms ECDSA IEEE_P1363 signature encoding to DER encoding.
   *
   * <p>The IEEE_P1363 signature's format is r || s, where r and s are zero-padded and have the same
   * size in bytes as the order of the curve. For example, for NIST P-256 curve, r and s are
   * zero-padded to 32 bytes.
   *
   * <p>The DER signature is encoded using ASN.1 (https://tools.ietf.org/html/rfc5480#appendix-A):
   * ECDSA-Sig-Value :: = SEQUENCE { r INTEGER, s INTEGER }. In particular, the encoding is: 0x30 ||
   * totalLength || 0x02 || r's length || r || 0x02 || s's length || s.
   *
   * @param ieee ECDSA's signature in IEEE_P1363 format.
   * @return ECDSA's signature in DER format.
   * @throws GeneralSecurityException if ieee's length is zero, greater than 132-byte (corresponding
   *     to NIST P521) or not divisible by 2.
   */
  public static byte[] ecdsaIeee2Der(byte[] ieee) throws GeneralSecurityException {
    if (ieee.length % 2 != 0 || ieee.length == 0 || ieee.length > 132) {
      throw new GeneralSecurityException("Invalid IEEE_P1363 encoding");
    }
    byte[] r = toMinimalSignedNumber(Arrays.copyOf(ieee, ieee.length / 2));
    byte[] s = toMinimalSignedNumber(Arrays.copyOfRange(ieee, ieee.length / 2, ieee.length));

    int offset = 0;
    int length = 1 + 1 + r.length + 1 + 1 + s.length;
    byte[] der;
    if (length >= 128) {
      der = new byte[length + 3];
      der[offset++] = (byte) 0x30;
      der[offset++] = (byte) (0x80 + 0x01);
      der[offset++] = (byte) length;
    } else {
      der = new byte[length + 2];
      der[offset++] = (byte) 0x30;
      der[offset++] = (byte) length;
    }
    der[offset++] = (byte) 0x02;
    der[offset++] = (byte) r.length;
    System.arraycopy(r, 0, der, offset, r.length);
    offset += r.length;
    der[offset++] = (byte) 0x02;
    der[offset++] = (byte) s.length;
    System.arraycopy(s, 0, der, offset, s.length);
    return der;
  }

  /**
   * Transforms ECDSA DER signature encoding to IEEE_P1363 encoding.
   *
   * <p>The IEEE_P1363 signature's format is r || s, where r and s are zero-padded and have the same
   * size in bytes as the order of the curve. For example, for NIST P-256 curve, r and s are
   * zero-padded to 32 bytes.
   *
   * <p>The DER signature is encoded using ASN.1 (https://tools.ietf.org/html/rfc5480#appendix-A):
   * ECDSA-Sig-Value :: = SEQUENCE { r INTEGER, s INTEGER }. In particular, the encoding is: 0x30 ||
   * totalLength || 0x02 || r's length || r || 0x02 || s's length || s.
   *
   * @param der ECDSA's signature in DER encoding.
   * @param ieeeLength length of ECDSA signature's in IEEE_P1363's format which equals to 2 * (size
   *     of elliptic curve's field in bytes).
   * @return ECDSA's signature in IEEE_P1363 format.
   * @throws GeneralSecurityException if the signature is not valid DER encoding.
   */
  public static byte[] ecdsaDer2Ieee(byte[] der, int ieeeLength) throws GeneralSecurityException {
    if (!isValidDerEncoding(der)) {
      throw new GeneralSecurityException("Invalid DER encoding");
    }
    byte[] ieee = new byte[ieeeLength];
    int length = der[1] & 0xff;
    int offset = 1 /* 0x30 */ + 1 /* totalLength */;
    if (length >= 128) {
      offset++; // Long form length
    }
    offset++; // 0x02
    int rLength = der[offset++];
    int extraZero = 0;
    if (der[offset] == 0) {
      extraZero = 1;
    }
    System.arraycopy(
        der, offset + extraZero, ieee, ieeeLength / 2 - rLength + extraZero, rLength - extraZero);
    offset += rLength /* r byte array */ + 1 /* 0x02 */;
    int sLength = der[offset++];
    extraZero = 0;
    if (der[offset] == 0) {
      extraZero = 1;
    }
    System.arraycopy(
        der, offset + extraZero, ieee, ieeeLength - sLength + extraZero, sLength - extraZero);
    return ieee;
  }

  // Validates that the signature is in DER encoding, based on
  // https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki.
  public static boolean isValidDerEncoding(final byte[] sig) {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
    // * total-length: 1-byte or 2-byte length descriptor of everything that follows.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.

    if (sig.length
        < 1 /* 0x30 */
            + 1 /* total-length */
            + 1 /* 0x02 */
            + 1 /* R-length */
            + 1 /* R */
            + 1 /* 0x02 */
            + 1 /* S-length */
            + 1 /* S */) {
      // Signature is too short.
      return false;
    }

    // Checking bytes from left to right.

    // byte #1: a signature is of type 0x30 (compound).
    if (sig[0] != 0x30) {
      return false;
    }

    // byte #2 and maybe #3: the total length of the signature.
    int totalLen = sig[1] & 0xff;
    int totalLenLen = 1; // the length of the total length field, could be 2-byte.
    if (totalLen == 129) {
      // The signature is >= 128 bytes thus total length field is in long-form encoding and occupies
      // 2 bytes.
      totalLenLen = 2;
      // byte #3 is the total length.
      totalLen = sig[2] & 0xff;
      if (totalLen < 128) {
        // Length in long-form encoding must be >= 128.
        return false;
      }
    } else if (totalLen == 128 || totalLen > 129) {
      // Impossible values for the second byte.
      return false;
    }

    // Make sure the length covers the entire sig.
    if (totalLen != sig.length - 1 - totalLenLen) {
      return false;
    }

    // Start checking R.
    // Check whether the R element is an integer.
    if (sig[1 + totalLenLen] != 0x02) {
      return false;
    }
    // Extract the length of the R element.
    int rLen = sig[1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */] & 0xff;
    // Make sure the length of the S element is still inside the signature.
    if (1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */ + 1 /* rLen */ + rLen + 1 /* 0x02 */
        >= sig.length) {
      return false;
    }
    // Zero-length integers are not allowed for R.
    if (rLen == 0) {
      return false;
    }
    // Negative numbers are not allowed for R.
    if ((sig[3 + totalLenLen] & 0xff) >= 128) {
      return false;
    }
    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (rLen > 1 && (sig[3 + totalLenLen] == 0x00) && ((sig[4 + totalLenLen] & 0xff) < 128)) {
      return false;
    }

    // Start checking S.
    // Check whether the S element is an integer.
    if (sig[3 + totalLenLen + rLen] != 0x02) {
      return false;
    }
    // Extract the length of the S element.
    int sLen =
        sig[1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */ + 1 /* rLen */ + rLen + 1 /* 0x02 */] & 0xff;
    // Verify that the length of the signature matches the sum of the length of the elements.
    if (1 /* 0x30 */
            + totalLenLen
            + 1 /* 0x02 */
            + 1 /* rLen */
            + rLen
            + 1 /* 0x02 */
            + 1 /* sLen */
            + sLen
        != sig.length) {
      return false;
    }
    // Zero-length integers are not allowed for S.
    if (sLen == 0) {
      return false;
    }
    // Negative numbers are not allowed for S.
    if ((sig[5 + totalLenLen + rLen] & 0xff) >= 128) {
      return false;
    }
    // Null bytes at the start of S are not allowed, unless S would
    // otherwise be interpreted as a negative number.
    if (sLen > 1
        && (sig[5 + totalLenLen + rLen] == 0x00)
        && ((sig[6 + totalLenLen + rLen] & 0xff) < 128)) {
      return false;
    }

    return true;
  }

  /**
   * Returns the encoding size of a point on an elliptic curve.
   *
   * @param curve the elliptic curve
   * @param format the format used to encode the point
   * @return the size of an encoded point in bytes
   * @throws GeneralSecurityException if the point format is unknown or if the elliptic curve is not
   *     supported
   */
  public static int encodingSizeInBytes(EllipticCurve curve, PointFormatType format)
      throws GeneralSecurityException {
    int coordinateSize = fieldSizeInBytes(curve);
    switch (format) {
      case UNCOMPRESSED:
        return 2 * coordinateSize + 1;
      case DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
        return 2 * coordinateSize;
      case COMPRESSED:
        return coordinateSize + 1;
    }
    throw new GeneralSecurityException("unknown EC point format");
  }

  /**
   * Decodes an encoded point on an elliptic curve. This method checks that the encoded point is on
   * the curve.
   *
   * @param curve the elliptic curve
   * @param format the format used to enocde the point
   * @param encoded the encoded point
   * @return the point
   * @throws GeneralSecurityException if the encoded point is invalid or if the curve or format are
   *     not supported.
   * @deprecated use {#pointDecode}
   */
  @Deprecated
  public static ECPoint ecPointDecode(EllipticCurve curve, PointFormatType format, byte[] encoded)
      throws GeneralSecurityException {
    return pointDecode(curve, format, encoded);
  }

  /**
   * Decodes an encoded point on an elliptic curve. This method checks that the encoded point is on
   * the curve.
   *
   * @param curve the elliptic curve
   * @param format the format used to enocde the point
   * @param encoded the encoded point
   * @return the point
   * @throws GeneralSecurityException if the encoded point is invalid or if the curve or format are
   *     not supported.
   * @since 1.1.0
   */
  public static ECPoint pointDecode(CurveType curveType, PointFormatType format, byte[] encoded)
      throws GeneralSecurityException {
    return pointDecode(getCurveSpec(curveType).getCurve(), format, encoded);
  }

  /**
   * Decodes an encoded point on an elliptic curve. This method checks that the encoded point is on
   * the curve.
   *
   * @param curve the elliptic curve
   * @param format the format used to enocde the point
   * @param encoded the encoded point
   * @return the point
   * @throws GeneralSecurityException if the encoded point is invalid or if the curve or format are
   *     not supported.
   * @since 1.1.0
   */
  public static ECPoint pointDecode(EllipticCurve curve, PointFormatType format, byte[] encoded)
      throws GeneralSecurityException {
    int coordinateSize = fieldSizeInBytes(curve);
    switch (format) {
      case UNCOMPRESSED:
        {
          if (encoded.length != 2 * coordinateSize + 1) {
            throw new GeneralSecurityException("invalid point size");
          }
          if (encoded[0] != 4) {
            throw new GeneralSecurityException("invalid point format");
          }
          BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, coordinateSize + 1));
          BigInteger y =
              new BigInteger(1, Arrays.copyOfRange(encoded, coordinateSize + 1, encoded.length));
          ECPoint point = new ECPoint(x, y);
          checkPointOnCurve(point, curve);
          return point;
        }
      case DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
        {
          if (encoded.length != 2 * coordinateSize) {
            throw new GeneralSecurityException("invalid point size");
          }
          BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 0, coordinateSize));
          BigInteger y =
              new BigInteger(1, Arrays.copyOfRange(encoded, coordinateSize, encoded.length));
          ECPoint point = new ECPoint(x, y);
          checkPointOnCurve(point, curve);
          return point;
        }
      case COMPRESSED:
        {
          BigInteger p = getModulus(curve);
          if (encoded.length != coordinateSize + 1) {
            throw new GeneralSecurityException("compressed point has wrong length");
          }
          boolean lsb;
          if (encoded[0] == 2) {
            lsb = false;
          } else if (encoded[0] == 3) {
            lsb = true;
          } else {
            throw new GeneralSecurityException("invalid format");
          }
          BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));
          if (x.signum() == -1 || x.compareTo(p) >= 0) {
            throw new GeneralSecurityException("x is out of range");
          }
          BigInteger y = getY(x, lsb, curve);
          return new ECPoint(x, y);
        }
    }
    throw new GeneralSecurityException("invalid format:" + format);
  }

  /**
   * Encodes a point on an elliptic curve.
   *
   * @param curve the elliptic curve
   * @param format the format for the encoding
   * @param point the point to encode
   * @return the encoded key exchange
   * @throws GeneralSecurityException if the point is not on the curve or if the format is not
   *     supported.
   * @since 1.1.0
   */
  public static byte[] pointEncode(CurveType curveType, PointFormatType format, ECPoint point)
      throws GeneralSecurityException {
    return pointEncode(getCurveSpec(curveType).getCurve(), format, point);
  }

  /**
   * Encodes a point on an elliptic curve.
   *
   * @param curve the elliptic curve
   * @param format the format for the encoding
   * @param point the point to encode
   * @return the encoded key exchange
   * @throws GeneralSecurityException if the point is not on the curve or if the format is not
   *     supported.
   * @since 1.1.0
   */
  public static byte[] pointEncode(EllipticCurve curve, PointFormatType format, ECPoint point)
      throws GeneralSecurityException {
    checkPointOnCurve(point, curve);
    int coordinateSize = fieldSizeInBytes(curve);
    switch (format) {
      case UNCOMPRESSED:
        {
          byte[] encoded = new byte[2 * coordinateSize + 1];
          byte[] x = point.getAffineX().toByteArray();
          byte[] y = point.getAffineY().toByteArray();
          // Order of System.arraycopy is important because x,y can have leading 0's.
          System.arraycopy(y, 0, encoded, 1 + 2 * coordinateSize - y.length, y.length);
          System.arraycopy(x, 0, encoded, 1 + coordinateSize - x.length, x.length);
          encoded[0] = 4;
          return encoded;
        }
      case DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
        {
          byte[] encoded = new byte[2 * coordinateSize];
          byte[] x = point.getAffineX().toByteArray();
          if (x.length > coordinateSize) {
            // x has leading 0's, strip them.
            x = Arrays.copyOfRange(x, x.length - coordinateSize, x.length);
          }
          byte[] y = point.getAffineY().toByteArray();
          if (y.length > coordinateSize) {
            // y has leading 0's, strip them.
            y = Arrays.copyOfRange(y, y.length - coordinateSize, y.length);
          }
          System.arraycopy(y, 0, encoded, 2 * coordinateSize - y.length, y.length);
          System.arraycopy(x, 0, encoded, coordinateSize - x.length, x.length);
          return encoded;
        }
      case COMPRESSED:
        {
          byte[] encoded = new byte[coordinateSize + 1];
          byte[] x = point.getAffineX().toByteArray();
          System.arraycopy(x, 0, encoded, 1 + coordinateSize - x.length, x.length);
          encoded[0] = (byte) (point.getAffineY().testBit(0) ? 3 : 2);
          return encoded;
        }
    }
    throw new GeneralSecurityException("invalid format:" + format);
  }

  /**
   * Returns the ECParameterSpec for a named curve.
   *
   * @param curve the curve type
   * @return the ECParameterSpec for the curve.
   */
  public static ECParameterSpec getCurveSpec(CurveType curve) throws NoSuchAlgorithmException {
    switch (curve) {
      case NIST_P256:
        return getNistP256Params();
      case NIST_P384:
        return getNistP384Params();
      case NIST_P521:
        return getNistP521Params();
    }
    throw new NoSuchAlgorithmException("curve not implemented:" + curve);
  }

  /**
   * Returns an {@link ECPublicKey} from {@code x509PublicKey} which is an encoding of a public
   * key, encoded according to the ASN.1 type SubjectPublicKeyInfo.
   *
   * TODO(b/68672497): test that in Java one can always get this representation by using
   * {@link ECPublicKey#getEncoded), regardless of the provider.
   */
  public static ECPublicKey getEcPublicKey(final byte[] x509PublicKey)
      throws GeneralSecurityException {
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    return (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(x509PublicKey));
  }

  /**
   * Returns an {@link ECPublicKey} from {@code publicKey} that is a public key in point format
   * {@code pointFormat} on {@code curve}.
   */
  public static ECPublicKey getEcPublicKey(
      CurveType curve, PointFormatType pointFormat, final byte[] publicKey)
      throws GeneralSecurityException {
    return getEcPublicKey(getCurveSpec(curve), pointFormat, publicKey);
  }

  /**
   * Returns an {@link ECPublicKey} from {@code publicKey} that is a public key in point format
   * {@code pointFormat} on {@code curve}.
   */
  public static ECPublicKey getEcPublicKey(
      ECParameterSpec spec, PointFormatType pointFormat, final byte[] publicKey)
      throws GeneralSecurityException {
    ECPoint point = pointDecode(spec.getCurve(), pointFormat, publicKey);
    ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, spec);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    return (ECPublicKey) kf.generatePublic(pubSpec);
  }

  /**
   * Returns an {@code ECPublicKey} from {@code curve} type and {@code x} and {@code y} coordinates.
   */
  public static ECPublicKey getEcPublicKey(CurveType curve, final byte[] x, final byte[] y)
      throws GeneralSecurityException {
    ECParameterSpec ecParams = getCurveSpec(curve);
    BigInteger pubX = new BigInteger(1, x);
    BigInteger pubY = new BigInteger(1, y);
    ECPoint w = new ECPoint(pubX, pubY);
    checkPointOnCurve(w, ecParams.getCurve());
    ECPublicKeySpec spec = new ECPublicKeySpec(w, ecParams);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    return (ECPublicKey) kf.generatePublic(spec);
  }

  /**
   * Returns an {@code ECPrivateKey} from {@code pkcs8PrivateKey} which is an encoding of a private
   * key, encoded according to the ASN.1 type SubjectPublicKeyInfo.
   *
   * TODO(b/68672497): test that in Java one can always get this representation by using
   * {@link ECPrivateKey#getEncoded), regardless of the provider.
   */
  public static ECPrivateKey getEcPrivateKey(final byte[] pkcs8PrivateKey)
      throws GeneralSecurityException {
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    return (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8PrivateKey));
  }

  /** Returns an {@code ECPrivateKey} from {@code curve} type and {@code keyValue}. */
  public static ECPrivateKey getEcPrivateKey(CurveType curve, final byte[] keyValue)
      throws GeneralSecurityException {
    ECParameterSpec ecParams = getCurveSpec(curve);
    BigInteger privValue = new BigInteger(1, keyValue);
    ECPrivateKeySpec spec = new ECPrivateKeySpec(privValue, ecParams);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    return (ECPrivateKey) kf.generatePrivate(spec);
  }

  /** Generates a new key pair for {@code curve}. */
  public static KeyPair generateKeyPair(CurveType curve) throws GeneralSecurityException {
    return generateKeyPair(getCurveSpec(curve));
  }

  /** Generates a new key pair for {@code spec}. */
  public static KeyPair generateKeyPair(ECParameterSpec spec) throws GeneralSecurityException {
    KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("EC");
    keyGen.initialize(spec);
    return keyGen.generateKeyPair();
  }

  /**
   * Checks that the shared secret is on the curve of the private key, to prevent arithmetic errors
   * or fault attacks.
   */
  private static void validateSharedSecret(byte[] secret, ECPrivateKey privateKey)
      throws GeneralSecurityException {
    EllipticCurve privateKeyCurve = privateKey.getParams().getCurve();
    BigInteger x = new BigInteger(1, secret);
    if (x.signum() == -1 || x.compareTo(getModulus(privateKeyCurve)) >= 0) {
      throw new GeneralSecurityException("shared secret is out of range");
    }
    // This will throw if x is not a valid coordinate.
    getY(x, true /* lsb, doesn't matter here */, privateKeyCurve);
  }

  /* Generates the DH shared secret using {@code myPrivateKey} and {@code peerPublicKey} */
  public static byte[] computeSharedSecret(ECPrivateKey myPrivateKey, ECPublicKey peerPublicKey)
      throws GeneralSecurityException {
    validatePublicKeySpec(peerPublicKey, myPrivateKey);
    return computeSharedSecret(myPrivateKey, peerPublicKey.getW());
  }

  /**
   * Generates the DH shared secret using {@code myPrivateKey} and {@code publicPoint}
   *
   * @since 1.1.0
   */
  public static byte[] computeSharedSecret(ECPrivateKey myPrivateKey, ECPoint publicPoint)
      throws GeneralSecurityException {
    checkPointOnCurve(publicPoint, myPrivateKey.getParams().getCurve());
    // Explicitly reconstruct the peer public key using private key's spec.
    ECParameterSpec privSpec = myPrivateKey.getParams();
    ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(publicPoint, privSpec);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("EC");
    PublicKey publicKey = kf.generatePublic(publicKeySpec);
    KeyAgreement ka = EngineFactory.KEY_AGREEMENT.getInstance("ECDH");
    ka.init(myPrivateKey);
    try {
      ka.doPhase(publicKey, true /* lastPhase */);
      byte[] secret = ka.generateSecret();
      validateSharedSecret(secret, myPrivateKey);
      return secret;
    } catch (IllegalStateException ex) {
      // Due to CVE-2017-10176 some versions of OpenJDK might throw this unchecked exception,
      // converting it to a checked one to not crash the JVM. See also b/73760761.
      throw new GeneralSecurityException(ex.toString());
    }
  }

  private EllipticCurves() {}
}
