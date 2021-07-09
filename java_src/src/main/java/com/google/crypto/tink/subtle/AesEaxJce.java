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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class implements the EAX mode using AES.
 *
 * <p>EAX is an encryption mode proposed by Bellare, Rogaway and Wagner
 * (http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf). The encryption mode is an alternative to CCM
 * and has been proposed as a NIST standard:
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/eax/eax-spec.pdf
 *
 * <p>The parameter choices have been restricted to a small set of options:
 *
 * <ul>
 *   <li>The tag size is always 16 bytes
 *   <li>Nonces are chosen by the implementation at random. Their size is 12 or 16 bytes.
 * </ul>
 *
 * <p>Plans: The current implementation is slow since it uses JCA and only assumes that the
 * encryption modes "AES/ECB/NOPADDING" and "AES/CTR/NOPADDING" are implemented. Our plan is to
 * implement a native version of EAX.
 *
 * @since 1.0.0
 */
public final class AesEaxJce implements Aead {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;

  private static final ThreadLocal<Cipher> localEcbCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance("AES/ECB/NOPADDING");
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  private static final ThreadLocal<Cipher> localCtrCipher =
      new ThreadLocal<Cipher>() {
        @Override
        protected Cipher initialValue() {
          try {
            return EngineFactory.CIPHER.getInstance("AES/CTR/NOPADDING");
          } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
          }
        }
      };

  static final int BLOCK_SIZE_IN_BYTES = 16;
  static final int TAG_SIZE_IN_BYTES = 16;

  // The constants B and P derived from the key. These constants are used for computing an OMAC.
  private final byte[] b;
  private final byte[] p;

  private final SecretKeySpec keySpec;
  private final int ivSizeInBytes;

  @SuppressWarnings("InsecureCryptoUsage")
  public AesEaxJce(final byte[] key, int ivSizeInBytes) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException("Can not use AES-EAX in FIPS-mode.");
    }

    if (ivSizeInBytes != 12 && ivSizeInBytes != 16) {
      throw new IllegalArgumentException("IV size should be either 12 or 16 bytes");
    }
    this.ivSizeInBytes = ivSizeInBytes;
    Validators.validateAesKeySize(key.length);
    keySpec = new SecretKeySpec(key, "AES");
    Cipher ecb = localEcbCipher.get();
    ecb.init(Cipher.ENCRYPT_MODE, keySpec);
    byte[] block = ecb.doFinal(new byte[BLOCK_SIZE_IN_BYTES]);
    b = multiplyByX(block);
    p = multiplyByX(b);
  }

  /** Computes the xor of two byte arrays of equal size. */
  private static byte[] xor(final byte[] x, final byte[] y) {
    assert x.length == y.length;
    int len = x.length;
    byte[] res = new byte[len];
    for (int i = 0; i < len; i++) {
      res[i] = (byte) (x[i] ^ y[i]);
    }
    return res;
  }

  /**
   * Multiplies an element of the field GF(2)[x]/(x^128+x^7+x^2+x+1) by x.
   *
   * @param block a 16 byte block representing an element of the field using big endian order.
   */
  private static byte[] multiplyByX(final byte[] block) {
    byte[] res = new byte[BLOCK_SIZE_IN_BYTES];
    for (int i = 0; i < BLOCK_SIZE_IN_BYTES - 1; i++) {
      // Shifts byte array by 1 bit (this is ugly because bytes in Java are signed)
      res[i] = (byte) (((block[i] << 1) ^ ((block[i + 1] & 0xff) >>> 7)) & 0xff);
    }
    // Shifts the least significant block by 1 bit and reduces the msb modulo the polynomial.
    res[BLOCK_SIZE_IN_BYTES - 1] =
        (byte) ((block[BLOCK_SIZE_IN_BYTES - 1] << 1) ^ ((block[0] >> 7) & 0x87));
    return res;
  }

  /**
   * Pads the last block for OMAC. If the last block is smaller than 16 bytes then a bitstring
   * starting with 1 and followed by 0's is appended and the result is XORed with p. If the last
   * block is 16 bytes long then the last block is XORed with b.
   *
   * @param data A block or partial block of size 1 .. 16 bytes.
   * @return The padded block.
   */
  private byte[] pad(final byte[] data) {
    if (data.length == BLOCK_SIZE_IN_BYTES) {
      return xor(data, b);
    } else {
      byte[] res = Arrays.copyOf(p, BLOCK_SIZE_IN_BYTES);
      for (int i = 0; i < data.length; i++) {
        res[i] ^= data[i];
      }
      res[data.length] = (byte) (res[data.length] ^ 0x80);
      return res;
    }
  }

  /**
   * Computes an OMAC.
   *
   * @param ecb A cipher initialized with the key of this class using AES/ECB/NOPadding and
   *     encryption mode.
   * @param tag The OMAC tag (0 for nonce, 1 for aad, 2 for ciphertext)
   * @param data The array containing the data to MAC.
   * @param offset The start of the data to MAC.
   * @param length The length of the data to MAC.
   * @return The 16 byte long OMAC
   * @throws IllegalBlockSizeException, BadPaddingException This should not happen.
   */
  private byte[] omac(Cipher ecb, int tag, final byte[] data, int offset, int length)
      throws IllegalBlockSizeException, BadPaddingException {
    assert length >= 0;
    assert 0 <= tag && tag <= 3;
    byte[] block = new byte[BLOCK_SIZE_IN_BYTES];
    block[BLOCK_SIZE_IN_BYTES - 1] = (byte) tag;
    if (length == 0) {
      return ecb.doFinal(xor(block, b));
    }
    block = ecb.doFinal(block);
    int position = 0;
    while (length - position > BLOCK_SIZE_IN_BYTES) {
      for (int i = 0; i < BLOCK_SIZE_IN_BYTES; i++) {
        block[i] ^= data[offset + position + i];
      }
      block = ecb.doFinal(block);
      position += BLOCK_SIZE_IN_BYTES;
    }
    byte[] padded = pad(Arrays.copyOfRange(data, offset + position, offset + length));
    block = xor(block, padded);
    return ecb.doFinal(block);
  }

  @SuppressWarnings("InsecureCryptoUsage")
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    // Check that ciphertext is not longer than the max. size of a Java array.
    if (plaintext.length > Integer.MAX_VALUE - ivSizeInBytes - TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("plaintext too long");
    }
    byte[] ciphertext = new byte[ivSizeInBytes + plaintext.length + TAG_SIZE_IN_BYTES];
    byte[] iv = Random.randBytes(ivSizeInBytes);
    System.arraycopy(iv, 0, ciphertext, 0, ivSizeInBytes);

    Cipher ecb = localEcbCipher.get();
    ecb.init(Cipher.ENCRYPT_MODE, keySpec);
    byte[] n = omac(ecb, 0, iv, 0, iv.length);
    byte[] aad = associatedData;
    if (aad == null) {
      aad = new byte[0];
    }
    byte[] h = omac(ecb, 1, aad, 0, aad.length);
    Cipher ctr = localCtrCipher.get();
    ctr.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(n));
    ctr.doFinal(plaintext, 0, plaintext.length, ciphertext, ivSizeInBytes);
    byte[] t = omac(ecb, 2, ciphertext, ivSizeInBytes, plaintext.length);
    int offset = plaintext.length + ivSizeInBytes;
    for (int i = 0; i < TAG_SIZE_IN_BYTES; i++) {
      ciphertext[offset + i] = (byte) (h[i] ^ n[i] ^ t[i]);
    }
    return ciphertext;
  }

  @SuppressWarnings("InsecureCryptoUsage")
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    int plaintextLength = ciphertext.length - ivSizeInBytes - TAG_SIZE_IN_BYTES;
    if (plaintextLength < 0) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    Cipher ecb = localEcbCipher.get();
    ecb.init(Cipher.ENCRYPT_MODE, keySpec);
    byte[] n = omac(ecb, 0, ciphertext, 0, ivSizeInBytes);
    byte[] aad = associatedData;
    if (aad == null) {
      aad = new byte[0];
    }
    byte[] h = omac(ecb, 1, aad, 0, aad.length);
    byte[] t = omac(ecb, 2, ciphertext, ivSizeInBytes, plaintextLength);
    byte res = 0;
    int offset = ciphertext.length - TAG_SIZE_IN_BYTES;
    for (int i = 0; i < TAG_SIZE_IN_BYTES; i++) {
      res = (byte) (res | (ciphertext[offset + i] ^ h[i] ^ n[i] ^ t[i]));
    }
    if (res != 0) {
      throw new AEADBadTagException("tag mismatch");
    }
    Cipher ctr = localCtrCipher.get();
    ctr.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(n));
    return ctr.doFinal(ciphertext, ivSizeInBytes, plaintextLength);
  }
}
