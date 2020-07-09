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

package com.google.crypto.tink.util;

import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Provides various utility methods for testing. */
public class TestUtil {

  private TestUtil() {}

  /**
   * Uses a z test on the given byte string, expecting all bits to be uniformly set with probability
   * 1/2. Returns non ok status if the z test fails by more than 10 standard deviations.
   *
   * <p>With less statistics jargon: This counts the number of bits set and expects the number to be
   * roughly half of the length of the string. The law of large numbers suggests that we can assume
   * that the longer the string is, the more accurate that estimate becomes for a random string.
   * This test is useful to detect things like strings that are entirely zero.
   *
   * <p>Note: By itself, this is a very weak test for randomness.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  public static void ztestUniformString(byte[] string) throws GeneralSecurityException {
    final double minAcceptableStdDevs = 10.0;
    double totalBits = string.length * 8;
    double expected = totalBits / 2.0;
    double stddev = Math.sqrt(totalBits / 4.0);

    // This test is very limited at low string lengths. Below a certain threshold it tests nothing.
    if (expected < stddev * minAcceptableStdDevs) {
      throw new GeneralSecurityException(
          "Test will always succeed with strings of the given length "
              + string.length
              + ". Use more bytes.");
    }

    long numSetBits = 0;
    for (byte b : string) {
      int unsignedInt = toUnsignedInt(b);
      // Counting the number of bits set in byte:
      while (unsignedInt != 0) {
        numSetBits++;
        unsignedInt = (unsignedInt & (unsignedInt - 1));
      }
    }
    // Check that the number of bits is within 10 stddevs.
    if (Math.abs((double) numSetBits - expected) < minAcceptableStdDevs * stddev) {
      return;
    }
    throw new GeneralSecurityException(
        "Z test for uniformly distributed variable out of bounds; "
            + "Actual number of set bits was "
            + numSetBits
            + " expected was "
            + expected
            + " 10 * standard deviation is 10 * "
            + stddev
            + " = "
            + 10.0 * stddev);
  }

  /**
   * Tests that the crosscorrelation of two strings of equal length points to independent and
   * uniformly distributed strings. Returns non ok status if the z test fails by more than 10
   * standard deviations.
   *
   * <p>With less statistics jargon: This xors two strings and then performs the ZTestUniformString
   * on the result. If the two strings are independent and uniformly distributed, the xor'ed string
   * is as well. A cross correlation test will find whether two strings overlap more or less than it
   * would be expected.
   *
   * <p>Note: Having a correlation of zero is only a necessary but not sufficient condition for
   * independence.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  public static void ztestCrossCorrelationUniformStrings(byte[] string1, byte[] string2)
      throws GeneralSecurityException {
    if (string1.length != string2.length) {
      throw new GeneralSecurityException("Strings are not of equal length");
    }
    byte[] crossed = new byte[string1.length];
    for (int i = 0; i < string1.length; i++) {
      crossed[i] = (byte) (string1[i] ^ string2[i]);
    }
    ztestUniformString(crossed);
  }

  /**
   * Tests that the autocorrelation of a string points to the bits being independent and uniformly
   * distributed. Rotates the string in a cyclic fashion. Returns non ok status if the z test fails
   * by more than 10 standard deviations.
   *
   * <p>With less statistics jargon: This rotates the string bit by bit and performs
   * ZTestCrosscorrelationUniformStrings on each of the rotated strings and the original. This will
   * find self similarity of the input string, especially periodic self similarity. For example, it
   * is a decent test to find English text (needs about 180 characters with the current settings).
   *
   * <p>Note: Having a correlation of zero is only a necessary but not sufficient condition for
   * independence.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  public static void ztestAutocorrelationUniformString(byte[] string)
      throws GeneralSecurityException {
    byte[] rotated = Arrays.copyOf(string, string.length);

    for (int i = 1; i < string.length * 8; i++) {
      rotate(rotated);
      ztestCrossCorrelationUniformStrings(string, rotated);
    }
  }

  /** Manual implementation of Byte.toUnsignedByte. The Android JDK does not have this method. */
  private static int toUnsignedInt(byte b) {
    return b & 0xff;
  }

  private static void rotate(byte[] string) {
    byte[] ref = Arrays.copyOf(string, string.length);
    for (int i = 0; i < string.length; i++) {
      string[i] =
          (byte)
              ((toUnsignedInt(string[i]) >> 1)
                  | ((1 & toUnsignedInt(ref[(i == 0 ? string.length : i) - 1])) << 7));
    }
  }
}
