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

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.AesGcmKey;
import com.google.crypto.tink.aead.internal.InsecureNonceAesGcmJce;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * This primitive implements AesGcm using JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class AesGcmJce implements Aead {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final InsecureNonceAesGcmJce insecureNonceAesGcmJce;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  private AesGcmJce(final byte[] key, Bytes outputPrefix) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
    }
    this.insecureNonceAesGcmJce = new InsecureNonceAesGcmJce(key, /*prependIv=*/ true);
    this.outputPrefix = outputPrefix.toByteArray();
  }

  public AesGcmJce(final byte[] key) throws GeneralSecurityException {
    this(key, Bytes.copyFrom(new byte[] {}));
  }

  @AccessesPartialKey
  public static Aead create(AesGcmKey key) throws GeneralSecurityException {
    if (key.getParameters().getIvSizeBytes() != InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES) {
      throw new GeneralSecurityException(
          "Expected IV Size 12, got " + key.getParameters().getIvSizeBytes());
    }
    if (key.getParameters().getTagSizeBytes() != InsecureNonceAesGcmJce.TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException(
          "Expected tag Size 16, got " + key.getParameters().getTagSizeBytes());
    }

    return new AesGcmJce(
        key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get()), key.getOutputPrefix());
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    byte[] iv = Random.randBytes(InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
    if (outputPrefix.length == 0) {
      return insecureNonceAesGcmJce.encrypt(iv, plaintext, associatedData);
    } else {
      return com.google.crypto.tink.subtle.Bytes.concat(
          outputPrefix, insecureNonceAesGcmJce.encrypt(iv, plaintext, associatedData));
    }
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (outputPrefix.length == 0) {
      byte[] iv = Arrays.copyOf(ciphertext, InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
      return insecureNonceAesGcmJce.decrypt(iv, ciphertext, associatedData);
    } else {
      if (!isPrefix(outputPrefix, ciphertext)) {
        throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
      }
      byte[] ciphertextNoPrefix =
          Arrays.copyOfRange(ciphertext, outputPrefix.length, ciphertext.length);
      byte[] iv = Arrays.copyOf(ciphertextNoPrefix, InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES);
      return insecureNonceAesGcmJce.decrypt(iv, ciphertextNoPrefix, associatedData);
    }
  }
}
