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

import com.google.crypto.tink.subtle.Enums.HashType;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/** Helper methods. */
public final class SubtleUtil {

  /**
   * Returns the Ecdsa algorithm name corresponding to a hash type.
   *
   * @param hash the hash type
   * @return the JCE's Ecdsa algorithm name for the hash.
   * @throw GeneralSecurityExceptio if {@code hash} is not supported or is not safe for digital
   *     signature.
   */
  public static String toEcdsaAlgo(HashType hash) throws GeneralSecurityException {
    Validators.validateSignatureHash(hash);
    return hash + "withECDSA";
  }

  /**
   * Returns the RSA SSA (Signature with Appendix) PKCS1 algorithm name corresponding to a hash
   * type.
   *
   * @param hash the hash type.
   * @return the JCE's RSA SSA PKCS1 algorithm name for the hash.
   * @throw GeneralSecurityException if {@code hash} is not supported or is not safe for digital
   *     signature.
   */
  public static String toRsaSsaPkcs1Algo(HashType hash) throws GeneralSecurityException {
    Validators.validateSignatureHash(hash);
    return hash + "withRSA";
  }

  /**
   * Returns the digest algorithm name corresponding to a hash type.
   *
   * @param hash the hash type.
   * @return theh JCE's hash algorithm name.
   * @throw GeneralSecurityException if {@code hash} is not supported.
   */
  public static String toDigestAlgo(HashType hash) throws GeneralSecurityException {
    switch (hash) {
      case SHA1:
        return "SHA-1";
      case SHA224:
        return "SHA-224";
      case SHA256:
        return "SHA-256";
      case SHA384:
        return "SHA-384";
      case SHA512:
        return "SHA-512";
    }
    throw new GeneralSecurityException("Unsupported hash " + hash);
  }

  /**
   * Best-effort checks that this is Android.
   *
   * @return true if running on Android.
   */
  public static boolean isAndroid() {
    // https://developer.android.com/reference/java/lang/System#getProperties%28%29
    return "The Android Project".equals(System.getProperty("java.vendor"));
  }

  /** Returns the Android API level or -1 if Tink isn't running on Android */
  public static int androidApiLevel() {
    try {
      Class<?> buildVersion = Class.forName("android.os.Build$VERSION");
      return buildVersion.getDeclaredField("SDK_INT").getInt(null);
    } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
      return -1;
    }
  }

  /**
   * Converts an byte array to a nonnegative integer
   * (https://tools.ietf.org/html/rfc8017#section-4.1).
   *
   * @param bs the byte array to be converted to integer.
   * @return the corresponding integer.
   */
  public static BigInteger bytes2Integer(byte[] bs) {
    return new BigInteger(1, bs);
  }

  /**
   * Converts a nonnegative integer to a byte array of a specified length
   * (https://tools.ietf.org/html/rfc8017#section-4.2).
   *
   * @param num nonnegative integer to be converted.
   * @param intendedLength intended length of the resulting integer.
   * @return the corresponding byte array of length {@code intendedLength}.
   */
  public static byte[] integer2Bytes(BigInteger num, int intendedLength)
      throws GeneralSecurityException {
    byte[] b = num.toByteArray();
    if (b.length == intendedLength) {
      return b;
    }
    if (b.length > intendedLength + 1 /* potential leading zero */) {
      throw new GeneralSecurityException("integer too large");
    }
    if (b.length == intendedLength + 1) {
      if (b[0] == 0 /* leading zero */) {
        return Arrays.copyOfRange(b, 1, b.length);
      } else {
        throw new GeneralSecurityException("integer too large");
      }
    }
    // Left zero pad b.
    byte[] res = new byte[intendedLength];
    System.arraycopy(b, 0, res, intendedLength - b.length, b.length);
    return res;
  }

  /** Computes MGF1 as defined at https://tools.ietf.org/html/rfc8017#appendix-B.2.1. */
  public static byte[] mgf1(byte[] mgfSeed, int maskLen, HashType mgfHash)
      throws GeneralSecurityException {
    MessageDigest digest =
        EngineFactory.MESSAGE_DIGEST.getInstance(SubtleUtil.toDigestAlgo(mgfHash));
    int hLen = digest.getDigestLength();
    // Step 1. Check maskLen.
    // As max integer is only 2^31 - 1 which is smaller than the limit 2^32, this step is skipped.

    // Step 2, 3. Compute t.
    byte[] t = new byte[maskLen];
    int tPos = 0;
    for (int counter = 0; counter <= (maskLen - 1) / hLen; counter++) {
      digest.reset();
      digest.update(mgfSeed);
      digest.update(SubtleUtil.integer2Bytes(BigInteger.valueOf(counter), 4));
      byte[] c = digest.digest();
      System.arraycopy(c, 0, t, tPos, Math.min(c.length, t.length - tPos));
      tPos += c.length;
    }
    return t;
  }

  /**
   * Inserts {@code value} as unsigned into into {@code buffer}.
   *
   * <p>@throws GeneralSecurityException if not 0 <= value < 2^32.
   */
  public static void putAsUnsigedInt(ByteBuffer buffer, long value)
      throws GeneralSecurityException {
    if (!(0 <= value && value < 0x100000000L)) {
      throw new GeneralSecurityException("Index out of range");
    }
    buffer.putInt((int) value);
  }

  private SubtleUtil() {}
}
