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
 * Validation helper methods.
 */
public final class Validators {
  private static final String TYPE_URL_PREFIX = "type.googleapis.com/";
  /**
   * @throws GeneralSecurityException if {@code typeUrl} is in invalid format.
   */
  public static void validateTypeUrl(String typeUrl) throws GeneralSecurityException {
    if (!typeUrl.startsWith(TYPE_URL_PREFIX)) {
      throw new GeneralSecurityException(
          String.format(
              "Error: type URL %s is invalid; it must start with %s.\n",
              typeUrl,
              TYPE_URL_PREFIX));
    }
    if (typeUrl.length() == TYPE_URL_PREFIX.length()) {
      throw new GeneralSecurityException(
          String.format("Error: type URL %s is invalid; it has no message name.\n", typeUrl));
    }
  }

  /**
   * @throws GeneralSecurityException if the {@code sizeInBytes} is not a valid AES key size.
   */
  public static void validateAesKeySize(int sizeInBytes) throws GeneralSecurityException {
    if (sizeInBytes != 16 && sizeInBytes != 24 && sizeInBytes != 32) {
      throw new GeneralSecurityException("invalid AES key size");
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
}
