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

import java.security.SecureRandom;

/**
 * A simple wrapper of SecureRandom.
 */
public final class Random {
  private static final SecureRandom secureRandom = new SecureRandom();

  /**
   * @return a random byte array of size {@code size}.
   */
  public static byte[] randBytes(int size) {
    byte[] rand = new byte[size];
    secureRandom.nextBytes(rand);
    return rand;
  }

  /**
   * @return positive random int.
   */
  public static int randPositiveInt() {
    int result = 0;
    while (result == 0) {
      byte[] rand = randBytes(4);
      result = ((rand[0] & 0x7f) << 24)
          | ((rand[1] & 0xff) << 16)
          | ((rand[2] & 0xff) << 8)
          | (rand[3] & 0xff);
    }
    return result;
  }
}
