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

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Helper methods.
 */
// TODO(thaidn): tests these functions.
public final class SubtleUtil {
  /**
   * Best effort fix-timing array comparison.
   * @return true if two arrays are equal.
   */
  public static final boolean arrayEquals(final byte[] x, final byte[] y) {
    if (x == null || y == null) {
      return false;
    }
    if (x.length != y.length) {
      return false;
    }
    int res = 0;
    for (int i = 0; i < x.length; i++) {
      res |= x[i] ^ y[i];
    }
    return res == 0;
  }

  /**
   * Returns the concatenation of the input arrays in a single array. For example,
   * {@code concat(new byte[] {a, b}, new byte[] {}, new byte[] {c}} returns the array
   * {@code {a, b, c}}.
   *
   * @return a single array containing all the values from the source arrays, in order
   */
  public static byte[] concat(byte[]... chunks) throws GeneralSecurityException {
    int length = 0;
    for (byte[] chunk : chunks) {
      if (length > Integer.MAX_VALUE - chunk.length) {
        throw new GeneralSecurityException("exceeded size limit");
      }
      length += chunk.length;
    }
    byte[] res = new byte[length];
    int pos = 0;
    for (byte[] chunk : chunks) {
      System.arraycopy(chunk, 0, res, pos, chunk.length);
      pos += chunk.length;
    }
    return res;
  }

  /**
   * @throws GeneralSecurityException if the {@code sizeInBytes} is not a valid AES key size.
   */
  public static void validateAesKeySize(int sizeInBytes) throws GeneralSecurityException {
    if (sizeInBytes != 16 && sizeInBytes != 24 && sizeInBytes != 32) {
      throw new GeneralSecurityException("invalid Aes key size");
    }
  }

  /**
   * @throws GeneralSecurityException if {@code candidate} is negative
   * or larger than {@code maxExpected}.
   */
  public static void validateVersion(int candidate, int maxExpected)
      throws GeneralSecurityException {
    if (candidate < 0 || candidate > maxExpected) {
      throw new GeneralSecurityException(
          String.format(
              "key has version %d; only keys with version in range [0..%d] are supported",
              candidate,
              maxExpected));
    }
  }

  /**
   * Best-effort checks that this is Android.
   * @return true if running on Android.
   */
  public static boolean isAndroid() {
    try {
      Class.forName("android.app.Application", /*initialize=*/ false, null);
      return true;
    } catch (Exception e) {
      // If Application isn't loaded, it might as well not be Android.
      return false;
    }
  }

  /*
   * @throws IOException if {@code f} exists.
   */
  public static void validateNotExists(File f) throws IOException {
    if (f.exists()) {
      throw new IOException(
          String.format("%s exists, please choose another file\n", f.toString()));
    }
  }

  /**
   * @throws IOException if {@code f} does not exists.
   */
  public static void validateExists(File f) throws IOException {
    if (!f.exists()) {
      throw new IOException(
          String.format("Error: %s doesn't exist, please choose another file\n", f.toString()));
    }
  }

  private static final String TYPE_URL_PREFIX = "type.googleapis.com/";
  /**
   * @throws GeneralSecurityException if {@code typeUrl} is in invalid format.
   */
  public static void validateTypeUrl(String typeUrl) throws GeneralSecurityException {
    if (!typeUrl.startsWith(TYPE_URL_PREFIX)) {
      throw new GeneralSecurityException(
          String.format(
              "Error: type URL %s is invalid; it must start with %s\n",
              typeUrl,
              TYPE_URL_PREFIX));
    }
  }

  /**
   * Prints an error then exits.
   */
  public static void die(String error) {
    System.err.print(String.format("Error: %s\n", error));
    System.exit(1);
  }

  // TODO(thaidn): add checks for boundary conditions/overflows.
  /**
   * Transforms a passed value to a LSB first byte array with the size of
   * the specified capacity
   *
   * @param capacity size of the resulting byte array
   * @param value that should be represented as a byte array
   */
  public static byte[] intToByteArray(int capacity, int value) {
    final byte[] result = new byte[capacity];
    for (int i = 0; i < capacity; i++) {
      result[i] = (byte) ((value >> (8 * i)) & 0xFF);
    }
    return result;
  }

  /**
   * Transforms a passed LSB first byte array to an int
   *
   * @param bytes that should be transformed to a byte array
   */
  public static int byteArrayToInt(byte[] bytes) {
    return byteArrayToInt(bytes, bytes.length);
  }

  /**
   * Transforms a passed LSB first byte array to an int
   *
   * @param bytes that should be transformed to a byte array
   * @param length amount of the passed {@code bytes} that should be transformed
   */
  public static int byteArrayToInt(byte[] bytes, int length) {
    return byteArrayToInt(bytes, 0, length);
  }

  /**
   * Transforms a passed LSB first byte array to an int
   *
   * @param bytes that should be transformed to a byte array
   * @param offset start index to start the transformation
   * @param length amount of the passed {@code bytes} that should be transformed
   */
  public static int byteArrayToInt(byte[] bytes, int offset, int length) {
    int value = 0;
    for (int i = 0; i < length; i++) {
      value += (bytes[i + offset] & 0xFF) << (i * 8);
    }
    return value;
  }
}
