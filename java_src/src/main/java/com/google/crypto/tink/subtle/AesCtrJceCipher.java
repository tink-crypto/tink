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
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The primitive implements AES counter mode with random IVs, using JCE.
 *
 * <h3>Warning</h3>
 *
 * <p>It is safe against chosen-plaintext attacks, but does not provide ciphertext integrity, thus
 * is unsafe against chosen-ciphertext attacks.
 *
 * @since 1.0.0
 */
public final class AesCtrJceCipher implements IndCpaCipher {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final ThreadLocal<Cipher> localCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance(CIPHER_ALGORITHM);
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  private static final String KEY_ALGORITHM = "AES";
  private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";

  // In counter mode each message is encrypted with an initialization vector (IV) that must be
  // unique. If one single IV is ever used to encrypt two or more messages, the confidentiality of
  // these messages might be lost. This cipher uses a randomly generated IV for each message. The
  // birthday paradox says that if one encrypts 2^k messages, the probability that the random IV
  // will repeat is roughly 2^{2k - t}, where t is the size in bits of the IV. Thus with 96-bit
  // (12-byte) IV, if one encrypts 2^32 messages the probability of IV collision is less than
  // 2^-33 (i.e., less than one in eight billion).
  private static final int MIN_IV_SIZE_IN_BYTES = 12;

  private final SecretKeySpec keySpec;
  private final int ivSize;
  private final int blockSize;

  public AesCtrJceCipher(final byte[] key, int ivSize) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use AES-CTR in FIPS-mode, as BoringCrypto module is not available.");
    }

    Validators.validateAesKeySize(key.length);
    this.keySpec = new SecretKeySpec(key, KEY_ALGORITHM);
    this.blockSize = localCipher.get().getBlockSize();
    if (ivSize < MIN_IV_SIZE_IN_BYTES || ivSize > blockSize) {
      throw new GeneralSecurityException("invalid IV size");
    }
    this.ivSize = ivSize;
  }

  /**
   * Encrypts the plaintext with counter mode encryption using randomly generated iv. The output
   * format is iv || raw ciphertext.
   *
   * @param plaintext the plaintext to be encrypted.
   * @return the encryption of plaintext.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - ivSize) {
      throw new GeneralSecurityException(
          "plaintext length can not exceed " + (Integer.MAX_VALUE - ivSize));
    }
    byte[] ciphertext = new byte[ivSize + plaintext.length];
    byte[] iv = Random.randBytes(ivSize);
    System.arraycopy(iv, 0, ciphertext, 0, ivSize);
    doCtr(plaintext, 0, plaintext.length, ciphertext, ivSize, iv, true);
    return ciphertext;
  }

  /**
   * Decrypts the ciphertext with counter mode decryption. The ciphertext format is iv || raw
   * ciphertext.
   *
   * @param ciphertext the ciphertext to be decrypted.
   * @return the decrypted plaintext.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext) throws GeneralSecurityException {
    if (ciphertext.length < ivSize) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] iv = new byte[ivSize];
    System.arraycopy(ciphertext, 0, iv, 0, ivSize);
    byte[] plaintext = new byte[ciphertext.length - ivSize];
    doCtr(ciphertext, ivSize, ciphertext.length - ivSize, plaintext, 0, iv, false);
    return plaintext;
  }

  private void doCtr(
      final byte[] input,
      int inputOffset,
      int inputLen,
      byte[] output,
      int outputOffset,
      final byte[] iv,
      boolean encrypt)
      throws GeneralSecurityException {
    Cipher cipher = localCipher.get();
    // The counter is big-endian. The counter is composed of iv and (blockSize - ivSize) of zeros.
    byte[] counter = new byte[blockSize];
    System.arraycopy(iv, 0, counter, 0, ivSize);

    IvParameterSpec paramSpec = new IvParameterSpec(counter);
    if (encrypt) {
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
    } else {
      cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
    }
    int numBytes = cipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
    if (numBytes != inputLen) {
      throw new GeneralSecurityException("stored output's length does not match input's length");
    }
  }
}
