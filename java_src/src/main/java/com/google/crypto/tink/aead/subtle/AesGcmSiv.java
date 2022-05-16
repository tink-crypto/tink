// Copyright 2017 Google Inc.
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //      http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
// //
// ////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.aead.subtle;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Random;
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
 * This primitive implements AES-GCM-SIV (as defined in RFC 8452) using JCE.
 *
 * <p>This encryption mode is intended for authenticated encryption with associated data. A major
 * security problem with AES-GCM is that reusing the same nonce twice leaks the authentication key.
 * AES-GCM-SIV on the other hand has been designed to avoid this vulnerability.
 *
 * <p>This encryption requires a JCE provider that supports the <code>AES/GCM-SIV/NoPadding</code>
 * transformation such as <a href="https://conscrypt.org">Conscrypt</a>. using JCE.
 */
@Alpha
public final class AesGcmSiv implements Aead {
  private static final ThreadLocal<Cipher> localCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance("AES/GCM-SIV/NoPadding");
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  // All instances of this class use a 12 byte IV and a 16 byte tag.
  private static final int IV_SIZE_IN_BYTES = 12;
  private static final int TAG_SIZE_IN_BYTES = 16;

  private final SecretKey keySpec;

  public AesGcmSiv(final byte[] key) throws GeneralSecurityException {
    Validators.validateAesKeySize(key.length);
    keySpec = new SecretKeySpec(key, "AES");
  }

  /**
   * On Android KitKat (API level 19) this method does not support non null or non empty {@code
   * associatedData}. It might not work at all in older versions.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    // Check that ciphertext is not longer than the max. size of a Java array.
    if (plaintext.length > Integer.MAX_VALUE - IV_SIZE_IN_BYTES - TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    byte[] ciphertext = new byte[IV_SIZE_IN_BYTES + plaintext.length + TAG_SIZE_IN_BYTES];
    byte[] iv = Random.randBytes(IV_SIZE_IN_BYTES);
    System.arraycopy(iv, 0, ciphertext, 0, IV_SIZE_IN_BYTES);

    AlgorithmParameterSpec params = getParams(iv);
    localCipher.get().init(Cipher.ENCRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      localCipher.get().updateAAD(associatedData);
    }
    int written =
        localCipher.get().doFinal(plaintext, 0, plaintext.length, ciphertext, IV_SIZE_IN_BYTES);
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
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext.length < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }

    AlgorithmParameterSpec params = getParams(ciphertext, 0, IV_SIZE_IN_BYTES);
    localCipher.get().init(Cipher.DECRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      localCipher.get().updateAAD(associatedData);
    }
    return localCipher
        .get()
        .doFinal(ciphertext, IV_SIZE_IN_BYTES, ciphertext.length - IV_SIZE_IN_BYTES);
  }

  private static AlgorithmParameterSpec getParams(final byte[] iv) throws GeneralSecurityException {
    return getParams(iv, 0, iv.length);
  }

  private static AlgorithmParameterSpec getParams(final byte[] buf, int offset, int len)
      throws GeneralSecurityException {
    try {
      Class.forName("javax.crypto.spec.GCMParameterSpec");
      return new GCMParameterSpec(8 * TAG_SIZE_IN_BYTES, buf, offset, len);
    } catch (ClassNotFoundException e) {
      if (SubtleUtil.isAndroid()) {
        // GCMParameterSpec should always be present in Java 7 or newer, but it's missing on Android
        // devices with API level < 19. Fortunately, with a modern copy of Conscrypt (either through
        // GMS or bundled with the app) we can initialize the cipher with just an IvParameterSpec.
        // It will use a tag size of 128 bits. We'd double check the tag size in encrypt().
        return new IvParameterSpec(buf, offset, len);
      }
    }
    throw new GeneralSecurityException(
        "cannot use AES-GCM: javax.crypto.spec.GCMParameterSpec not found");
  }
}
