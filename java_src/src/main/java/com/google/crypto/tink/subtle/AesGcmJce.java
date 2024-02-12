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
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This primitive implements AesGcm using JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class AesGcmJce implements Aead {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  private static final int IV_SIZE_IN_BYTES = InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES;
  private static final int TAG_SIZE_IN_BYTES = InsecureNonceAesGcmJce.TAG_SIZE_IN_BYTES;

  @SuppressWarnings("Immutable")
  private final SecretKey keySpec;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  private AesGcmJce(final byte[] key, Bytes outputPrefix) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
    }
    Validators.validateAesKeySize(key.length);
    this.keySpec = new SecretKeySpec(key, "AES");
    this.outputPrefix = outputPrefix.toByteArray();
  }

  public AesGcmJce(final byte[] key) throws GeneralSecurityException {
    this(key, Bytes.copyFrom(new byte[] {}));
  }

  @AccessesPartialKey
  public static Aead create(AesGcmKey key) throws GeneralSecurityException {
    if (key.getParameters().getIvSizeBytes() != IV_SIZE_IN_BYTES) {
      throw new GeneralSecurityException(
          "Expected IV Size 12, got " + key.getParameters().getIvSizeBytes());
    }
    if (key.getParameters().getTagSizeBytes() != TAG_SIZE_IN_BYTES) {
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
    if (plaintext == null) {
      throw new NullPointerException("plaintext is null");
    }
    byte[] nonce = Random.randBytes(IV_SIZE_IN_BYTES);
    AlgorithmParameterSpec params = InsecureNonceAesGcmJce.getParams(nonce);
    Cipher cipher = InsecureNonceAesGcmJce.getThreadLocalCipher();
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      cipher.updateAAD(associatedData);
    }
    int outputSize = cipher.getOutputSize(plaintext.length);
    if (outputSize > Integer.MAX_VALUE - outputPrefix.length - IV_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    int len = outputPrefix.length + IV_SIZE_IN_BYTES + outputSize;
    byte[] output = Arrays.copyOf(outputPrefix, len);
    System.arraycopy(
        /* src= */ nonce,
        /* srcPos= */ 0,
        /* dest= */ output,
        /* destPos= */ outputPrefix.length,
        /* length= */ IV_SIZE_IN_BYTES);
    int written =
        cipher.doFinal(
            plaintext, 0, plaintext.length, output, outputPrefix.length + IV_SIZE_IN_BYTES);
    if (written != outputSize) {
      throw new GeneralSecurityException("not enough data written");
    }
    return output;
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext == null) {
      throw new NullPointerException("ciphertext is null");
    }
    if (ciphertext.length < outputPrefix.length + IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    if (!isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
    }
    byte[] nonce = new byte[IV_SIZE_IN_BYTES];
    System.arraycopy(
        /* src= */ ciphertext,
        /* srcPos= */ outputPrefix.length,
        /* dest= */ nonce,
        /* destPos= */ 0,
        /* length= */ IV_SIZE_IN_BYTES);
    AlgorithmParameterSpec params = InsecureNonceAesGcmJce.getParams(nonce);

    Cipher cipher = InsecureNonceAesGcmJce.getThreadLocalCipher();
    cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
    if (associatedData != null && associatedData.length != 0) {
      cipher.updateAAD(associatedData);
    }
    int offset = outputPrefix.length + IV_SIZE_IN_BYTES;
    int len = ciphertext.length - outputPrefix.length - IV_SIZE_IN_BYTES;
    return cipher.doFinal(ciphertext, offset, len);
  }
}
