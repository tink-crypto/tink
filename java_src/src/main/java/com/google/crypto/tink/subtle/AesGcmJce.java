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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.aead.internal.InsecureNonceAesGcmJce;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * This primitive implements AesGcm using JCE.
 *
 * @since 1.0.0
 */
public final class AesGcmJce implements Aead {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private final InsecureNonceAesGcmJce insecureNonceAesGcmJce;

  public AesGcmJce(final byte[] key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
    }
    this.insecureNonceAesGcmJce = new InsecureNonceAesGcmJce(key, /*prependIv=*/ true);
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
    return insecureNonceAesGcmJce.encrypt(iv, plaintext, associatedData);
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    byte[] iv = Arrays.copyOf(ciphertext, InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
    return insecureNonceAesGcmJce.decrypt(iv, ciphertext, associatedData);
  }
}
