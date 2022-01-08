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
 * A simple wrapper of {@link SecureRandom}.
 *
 * @since 1.0.0
 */
public final class Random {
  private static final ThreadLocal<SecureRandom> localRandom = new ThreadLocal<SecureRandom>() {
    @Override
    protected SecureRandom initialValue() {
      return newDefaultSecureRandom();
    }
  };

  private static SecureRandom newDefaultSecureRandom() {
    SecureRandom retval = new SecureRandom();
    retval.nextLong(); // force seeding
    return retval;
  }

  /** @return a random byte array of size {@code size}. */
  public static byte[] randBytes(int size) {
    byte[] rand = new byte[size];
    localRandom.get().nextBytes(rand);
    return rand;
  }

  public static final int randInt(int max) {
    return localRandom.get().nextInt(max);
  }

  public static final int randInt() {
    return localRandom.get().nextInt();
  }

  private Random() {}
}
