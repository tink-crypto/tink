// Copyright 2020 Google LLC
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

package com.google.crypto.tink.hybrid.subtle;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

class RsaKem {
  static final byte[] EMPTY_AAD = new byte[0];
  static final int MIN_RSA_KEY_LENGTH_BITS = 2048;

  private RsaKem() {}

  static void validateRsaModulus(BigInteger mod) throws GeneralSecurityException {
    if (mod.bitLength() < MIN_RSA_KEY_LENGTH_BITS) {
      throw new GeneralSecurityException(
          String.format(
              "RSA key must be of at least size %d bits, but got %d",
              MIN_RSA_KEY_LENGTH_BITS, mod.bitLength()));
    }
  }

  static int bigIntSizeInBytes(BigInteger mod) {
    return (mod.bitLength() + 7) / 8;
  }

  /**
   * Converts {@code bigInt} to a fixed-size byte array, by taking away at most one leading zero
   * (the sign byte), or adding leading zeros.
   */
  static byte[] bigIntToByteArray(BigInteger bigInt, int size) {
    byte[] value = bigInt.toByteArray();
    if (value.length == size) {
      return value;
    }

    byte[] result = new byte[size];
    if (value.length == result.length + 1) {
      if (value[0] != 0) {
        throw new IllegalArgumentException(
            "Value is one-byte longer than the expected size, but its first byte is not 0");
      }
      System.arraycopy(value, 1, result, 0, result.length);
    } else if (value.length < result.length) {
      System.arraycopy(value, 0, result, result.length - value.length, value.length);
    } else {
      throw new IllegalArgumentException(
          String.format(
              "Value has invalid length, must be of length at most (%d + 1), but" + " got %d",
              size, value.length));
    }
    return result;
  }

  /**
   * Generates a random BigInteger in (0, max) (excluding 0 and max) and converts the result to a
   * byte array having the same length as max.
   */
  static byte[] generateSecret(BigInteger max) {
    int maxSizeInBytes = bigIntSizeInBytes(max);
    Random rand = new SecureRandom();
    BigInteger r;
    do {
      r = new BigInteger(max.bitLength(), rand);
    } while (r.signum() <= 0 || r.compareTo(max) >= 0);

    return bigIntToByteArray(r, maxSizeInBytes);
  }

  static KeyPair generateRsaKeyPair(int keySize) {
    KeyPairGenerator rsaGenerator;
    try {
      rsaGenerator = KeyPairGenerator.getInstance("RSA");
      rsaGenerator.initialize(keySize);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("No support for RSA algorithm.", e);
    }
    return rsaGenerator.generateKeyPair();
  }
}
