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

import com.google.crypto.tink.prf.Prf;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/** {@link Prf} implementation using JCE. */
@Immutable
public final class PrfHmacJce implements Prf {
  static final int MIN_KEY_SIZE_IN_BYTES = 16;

  @SuppressWarnings("Immutable")  // We do not mutate the underlying mac.
  private final javax.crypto.Mac mac;

  private final String algorithm;
  @SuppressWarnings("Immutable")  // We do not mutate the key.
  private final java.security.Key key;

  private final int maxOutputLength;

  public PrfHmacJce(String algorithm, java.security.Key key) throws GeneralSecurityException {
    this.algorithm = algorithm;
    this.key = key;
    this.mac = EngineFactory.MAC.getInstance(algorithm);
    if (key.getEncoded().length < MIN_KEY_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "key size too small, need at least " + MIN_KEY_SIZE_IN_BYTES + " bytes");
    }

    switch (algorithm) {
      case "HMACSHA1":
        maxOutputLength = 20;
        break;
      case "HMACSHA256":
        maxOutputLength = 32;
        break;
      case "HMACSHA512":
        maxOutputLength = 64;
        break;
      default:
        throw new NoSuchAlgorithmException("unknown Hmac algorithm: " + algorithm);
    }
    mac.init(key);
  }

  @Override
  public byte[] compute(byte[] data, int outputLength) throws GeneralSecurityException {
    if (outputLength > maxOutputLength) {
      throw new InvalidAlgorithmParameterException("tag size too big");
    }

    javax.crypto.Mac tmp;
    try {
      // Cloning a mac is frequently fast and thread-safe.
      tmp = (javax.crypto.Mac) this.mac.clone();
    } catch (java.lang.CloneNotSupportedException ex) {
      // Unfortunately, the Mac interface in certain versions of Android is not clonable.
      tmp = EngineFactory.MAC.getInstance(this.algorithm);
      tmp.init(this.key);
    }
    tmp.update(data);
    return Arrays.copyOf(tmp.doFinal(), outputLength);
  }

  /** Returns the maximum supported tag length. */
  public int getMaxOutputLength() {
    return maxOutputLength;
  }
}
