// Copyright 2021 Google LLC
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

package com.google.crypto.tink.aead.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements ChaCha20Poly1305, as described in <a
 * href="https://tools.ietf.org/html/rfc8439#section-2.8">RFC 8439, section 2.8</a>.
 *
 * <p>It is similar to {@link ChaCha20Poly1305Jce}, but it offers an interface for the user to
 * choose the nonce, which is needed in HPKE.
 *
 * <p>It uses the JCE, and requires that algorithm "ChaCha20-Poly1305" is present.
 */
@Immutable
public final class InsecureNonceChaCha20Poly1305Jce {

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final int NONCE_SIZE_IN_BYTES = 12;
  private static final int TAG_SIZE_IN_BYTES = 16;
  private static final int KEY_SIZE_IN_BYTES = 32;

  private static final String CIPHER_NAME = "ChaCha20-Poly1305";
  private static final String KEY_NAME = "ChaCha20";

  @SuppressWarnings("Immutable")
  private final SecretKey keySpec;

  private InsecureNonceChaCha20Poly1305Jce(final byte[] key) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use ChaCha20Poly1305 in FIPS-mode.");
    }
    if (!isSupported()) {
      throw new GeneralSecurityException("JCE does not support algorithm: " + CIPHER_NAME);
    }
    if (key.length != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException("The key length in bytes must be 32.");
    }
    this.keySpec = new SecretKeySpec(key, KEY_NAME);
  }

  @AccessesPartialKey
  public static InsecureNonceChaCha20Poly1305Jce create(final byte[] key)
      throws GeneralSecurityException {
    return new InsecureNonceChaCha20Poly1305Jce(key);
  }

  public static boolean isSupported() {
    return ChaCha20Poly1305Jce.getThreadLocalCipherOrNull() != null;
  }

  public byte[] encrypt(final byte[] nonce, final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (plaintext == null) {
      throw new NullPointerException("plaintext is null");
    }
    if (nonce.length != NONCE_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("nonce length must be " + NONCE_SIZE_IN_BYTES + " bytes.");
    }
    AlgorithmParameterSpec params = new IvParameterSpec(nonce);
    Cipher cipher = ChaCha20Poly1305Jce.getThreadLocalCipherOrNull();
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      cipher.updateAAD(associatedData);
    }
    return cipher.doFinal(plaintext);
  }

  public byte[] decrypt(final byte[] nonce, final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext == null) {
      throw new NullPointerException("ciphertext is null");
    }
    if (nonce.length != NONCE_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("nonce length must be " + NONCE_SIZE_IN_BYTES + " bytes.");
    }
    if (ciphertext.length < TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    AlgorithmParameterSpec params = new IvParameterSpec(nonce);

    Cipher cipher = ChaCha20Poly1305Jce.getThreadLocalCipherOrNull();
    cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      cipher.updateAAD(associatedData);
    }
    return cipher.doFinal(ciphertext);
  }
}
