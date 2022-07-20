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

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.prf.Prf;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;

/** {@link Prf} implementation using JCE. */
@Immutable
public final class PrfHmacJce implements Prf {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  static final int MIN_KEY_SIZE_IN_BYTES = 16;

  // We do not mutate the underlying mac and it is bound to the containing PrfHmacJce instance.
  @SuppressWarnings({"Immutable", "ThreadLocalUsage"})
  private final ThreadLocal<Mac> localMac =
      new ThreadLocal<Mac>() {
        @Override
        protected Mac initialValue() {
          try {
            Mac mac = EngineFactory.MAC.getInstance(algorithm);
            mac.init(key);
            return mac;
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  private final String algorithm;
  @SuppressWarnings("Immutable")  // We do not mutate the key.
  private final java.security.Key key;

  private final int maxOutputLength;

  public PrfHmacJce(String algorithm, java.security.Key key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use HMAC in FIPS-mode, as BoringCrypto module is not available.");
    }

    this.algorithm = algorithm;
    this.key = key;
    if (key.getEncoded().length < MIN_KEY_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "key size too small, need at least " + MIN_KEY_SIZE_IN_BYTES + " bytes");
    }

    switch (algorithm) {
      case "HMACSHA1":
        maxOutputLength = 20;
        break;
      case "HMACSHA224":
        maxOutputLength = 28;
        break;
      case "HMACSHA256":
        maxOutputLength = 32;
        break;
      case "HMACSHA384":
        maxOutputLength = 48;
        break;
      case "HMACSHA512":
        maxOutputLength = 64;
        break;
      default:
        throw new NoSuchAlgorithmException("unknown Hmac algorithm: " + algorithm);
    }

    // Initialize the current threads mac, mostly to fail fast if anything is wrong.
    localMac.get();
  }

  @Override
  public byte[] compute(byte[] data, int outputLength) throws GeneralSecurityException {
    if (outputLength > maxOutputLength) {
      throw new InvalidAlgorithmParameterException("tag size too big");
    }

    localMac.get().update(data);
    return Arrays.copyOf(localMac.get().doFinal(), outputLength);
  }

  /** Returns the maximum supported tag length. */
  public int getMaxOutputLength() {
    return maxOutputLength;
  }
}
