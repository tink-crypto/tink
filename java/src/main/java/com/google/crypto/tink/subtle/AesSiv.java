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

import com.google.crypto.tink.DeterministicAead;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-SIV, as described in <a href="https://tools.ietf.org/html/rfc5297">RFC 5297</a>.
 *
 * <p>To meet the security requirements of {@link DeterministicAead}, this cipher can only be used
 * with 256-bit keys.
 *
 * @since 1.1.0
 */
public final class AesSiv implements DeterministicAead {
  // Do not support 128-bit keys because it might not provide 128-bit security level in
  // multi-user setting.
  private static final Collection<Integer> KEY_SIZES = Arrays.asList(64);
  private static final byte[] BLOCK_ZERO = new byte[AesUtil.BLOCK_SIZE];
  private static final byte[] BLOCK_ONE = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x01
  };

  /** The internal AesCmac object for S2V */
  private final AesCmac cmacForS2V;

  /** The key used for the CTR encryption */
  private final byte[] aesCtrKey;

  public AesSiv(final byte[] key) throws GeneralSecurityException {
    if (!KEY_SIZES.contains(key.length)) {
      throw new InvalidKeyException(
          "invalid key size: " + key.length + " bytes; key must have 64 bytes");
    }

    byte[] k1 = Arrays.copyOfRange(key, 0, key.length / 2);
    this.aesCtrKey = Arrays.copyOfRange(key, key.length / 2, key.length);
    this.cmacForS2V = new AesCmac(k1, AesUtil.BLOCK_SIZE);
  }

  /**
   * s2v per https://tools.ietf.org/html/rfc5297
   *
   * @param s
   * @return s2v(si)
   * @throws GeneralSecurityException
   */
  private byte[] s2v(final byte[]... s) throws GeneralSecurityException {
    if (s.length == 0) {
      // Should never happen with AES-SIV, but we include this for completeness.
      return cmacForS2V.computeMac(BLOCK_ONE);
    }

    byte[] result = cmacForS2V.computeMac(BLOCK_ZERO);
    for (int i = 0; i < s.length - 1; i++) {
      result = Bytes.xor(AesUtil.dbl(result), cmacForS2V.computeMac(s[i]));
    }
    byte[] lastBlock = s[s.length - 1];
    if (lastBlock.length >= 16) {
      result = Bytes.xorEnd(lastBlock, result);
    } else {
      result = Bytes.xor(AesUtil.cmacPad(lastBlock), AesUtil.dbl(result));
    }
    return cmacForS2V.computeMac(result);
  }

  @Override
  public byte[] encryptDeterministically(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - AesUtil.BLOCK_SIZE) {
      throw new GeneralSecurityException("plaintext too long");
    }

    Cipher aesCtr = EngineFactory.CIPHER.getInstance("AES/CTR/NoPadding");
    byte[] computedIv = s2v(associatedData, plaintext);
    byte[] ivForJavaCrypto = computedIv.clone();
    ivForJavaCrypto[8] &= (byte) 0x7F; // 63th bit from the right
    ivForJavaCrypto[12] &= (byte) 0x7F; // 31st bit from the right

    aesCtr.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(this.aesCtrKey, "AES"),
        new IvParameterSpec(ivForJavaCrypto));

    byte[] ctrCiphertext = aesCtr.doFinal(plaintext);
    return Bytes.concat(computedIv, ctrCiphertext);
  }

  @Override
  public byte[] decryptDeterministically(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext.length < AesUtil.BLOCK_SIZE) {
      throw new GeneralSecurityException("Ciphertext too short.");
    }

    Cipher aesCtr = EngineFactory.CIPHER.getInstance("AES/CTR/NoPadding");

    byte[] expectedIv = Arrays.copyOfRange(ciphertext, 0, AesUtil.BLOCK_SIZE);

    byte[] ivForJavaCrypto = expectedIv.clone();
    ivForJavaCrypto[8] &= (byte) 0x7F; // 63th bit from the right
    ivForJavaCrypto[12] &= (byte) 0x7F; // 31st bit from the right

    aesCtr.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(this.aesCtrKey, "AES"),
        new IvParameterSpec(ivForJavaCrypto));

    byte[] ctrCiphertext = Arrays.copyOfRange(ciphertext, AesUtil.BLOCK_SIZE, ciphertext.length);
    byte[] decryptedPt = aesCtr.doFinal(ctrCiphertext);
    if (ctrCiphertext.length == 0 && decryptedPt == null && SubtleUtil.isAndroid()) {
      // On Android KitKat (19) and Lollipop (21), Cipher.doFinal returns a null pointer when the
      // ciphertext is empty, instead of an empty plaintext. Here we attempt to fix this bug. This
      // is safe because if the plaintext is not empty, the next integrity check would reject it.
      decryptedPt = new byte[0];
    }
    byte[] computedIv = s2v(associatedData, decryptedPt);

    if (Bytes.equal(expectedIv, computedIv)) {
      return decryptedPt;
    } else {
      throw new AEADBadTagException("Integrity check failed.");
    }
  }
}
