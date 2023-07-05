// Copyright 2023 Google LLC
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

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/** Provides secure randomness using {@link SecureRandom}. */
public final class Random {
  private static final ThreadLocal<SecureRandom> localRandom =
      new ThreadLocal<SecureRandom>() {
        @Override
        protected SecureRandom initialValue() {
          return newDefaultSecureRandom();
        }
      };

  private static SecureRandom create() {
    // Use Conscrypt if possible. Conscrypt may have three different provider names.
    // For legacy compatibility reasons it uses the algorithm name "SHA1PRNG".
    try {
      return SecureRandom.getInstance("SHA1PRNG", "GmsCore_OpenSSL");
    } catch (GeneralSecurityException e) {
      // ignore
    }
    try {
      return SecureRandom.getInstance("SHA1PRNG", "AndroidOpenSSL");
    } catch (GeneralSecurityException e) {
      // ignore
    }
    try {
      return SecureRandom.getInstance("SHA1PRNG", "Conscrypt");
    } catch (GeneralSecurityException e) {
      // ignore
    }
    return new SecureRandom();
  }

  private static SecureRandom newDefaultSecureRandom() {
    SecureRandom retval = create();
    retval.nextLong(); // force seeding
    return retval;
  }

  /** Returns a random byte array of size {@code size}. */
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

  /** Throws a GeneralSecurityException if the provider is not Conscrypt. */
  public static final void validateUsesConscrypt() throws GeneralSecurityException {
    String providerName = localRandom.get().getProvider().getName();
    if (!providerName.equals("GmsCore_OpenSSL")
        && !providerName.equals("AndroidOpenSSL")
        && !providerName.equals("Conscrypt")) {
      throw new GeneralSecurityException(
          "Requires GmsCore_OpenSSL, AndroidOpenSSL or Conscrypt to generate randomness, but got "
              + providerName);
    }
  }

  private Random() {}
}
