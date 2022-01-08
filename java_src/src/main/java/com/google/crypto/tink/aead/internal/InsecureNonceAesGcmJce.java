// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.aead.internal;

import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.SubtleUtil;
import com.google.crypto.tink.subtle.Validators;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Insecure version of {@link com.google.crypto.tink.subtle.AesGcmJce} that allows the caller to set
 * the IV.
 */
public final class InsecureNonceAesGcmJce {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  // All instances of this class use a 12-byte IV and a 16-byte tag.
  public static final int IV_SIZE_IN_BYTES = 12;
  public static final int TAG_SIZE_IN_BYTES = 16;

  private static final ThreadLocal<Cipher> localCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding");
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  private final SecretKey keySpec;
  private final boolean prependIv;

  public InsecureNonceAesGcmJce(final byte[] key, boolean prependIv)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
    }
    Validators.validateAesKeySize(key.length);
    this.keySpec = new SecretKeySpec(key, "AES");
    this.prependIv = prependIv;
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  public byte[] encrypt(final byte[] iv, final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (iv.length != IV_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("iv is wrong size");
    }
    // Check that ciphertext is not longer than the max. size of a Java array.
    if (plaintext.length > Integer.MAX_VALUE - IV_SIZE_IN_BYTES - TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    int ciphertextLength =
        prependIv
            ? IV_SIZE_IN_BYTES + plaintext.length + TAG_SIZE_IN_BYTES
            : plaintext.length + TAG_SIZE_IN_BYTES;
    byte[] ciphertext = new byte[ciphertextLength];
    if (prependIv) {
      System.arraycopy(iv, 0, ciphertext, 0, IV_SIZE_IN_BYTES);
    }

    AlgorithmParameterSpec params = getParams(iv);
    localCipher.get().init(Cipher.ENCRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      localCipher.get().updateAAD(associatedData);
    }
    int ciphertextOutputOffset = prependIv ? IV_SIZE_IN_BYTES : 0;
    int written =
        localCipher
            .get()
            .doFinal(plaintext, 0, plaintext.length, ciphertext, ciphertextOutputOffset);
    // For security reasons, AES-GCM encryption must always use tag of TAG_SIZE_IN_BYTES bytes. If
    // so, written must be equal to plaintext.length + TAG_SIZE_IN_BYTES.

    if (written != plaintext.length + TAG_SIZE_IN_BYTES) {
      // The tag is shorter than expected.
      int actualTagSize = written - plaintext.length;
      throw new GeneralSecurityException(
          String.format(
              "encryption failed; GCM tag must be %s bytes, but got only %s bytes",
              TAG_SIZE_IN_BYTES, actualTagSize));
    }
    return ciphertext;
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  public byte[] decrypt(final byte[] iv, final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (iv.length != IV_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("iv is wrong size");
    }
    if (ciphertext.length < TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }

    AlgorithmParameterSpec params = getParams(iv);
    localCipher.get().init(Cipher.DECRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      localCipher.get().updateAAD(associatedData);
    }
    int ciphertextInputOffset = prependIv ? IV_SIZE_IN_BYTES : 0;
    int ciphertextLength = prependIv ? ciphertext.length - IV_SIZE_IN_BYTES : ciphertext.length;
    return localCipher.get().doFinal(ciphertext, ciphertextInputOffset, ciphertextLength);
  }

  private static AlgorithmParameterSpec getParams(final byte[] iv) throws GeneralSecurityException {
    return getParams(iv, 0, iv.length);
  }

  private static AlgorithmParameterSpec getParams(final byte[] buf, int offset, int len)
      throws GeneralSecurityException {
    if (SubtleUtil.isAndroid() && SubtleUtil.androidApiLevel() <= 19) {
      // GCMParameterSpec should always be present in Java 7 or newer, but it's unsupported on
      // Android devices with API level <= 19. Fortunately, if a modern copy of Conscrypt is present
      // (either through GMS Core or bundled with the app) we can initialize the cipher with just an
      // IvParameterSpec.
      // It will use a tag size of 128 bits. We'd double check the tag size in encrypt().
      return new IvParameterSpec(buf, offset, len);
    }
    return new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, buf, offset, len);
  }
}
