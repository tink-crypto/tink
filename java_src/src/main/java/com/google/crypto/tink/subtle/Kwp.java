// Copyright 2018 Google Inc.
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

import com.google.crypto.tink.KeyWrap;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements the key wrapping primitive KWP defined in NIST SP 800 38f.
 * The same encryption mode is also defined in RFC 5649. The NIST document is used here
 * as a primary reference, since it contains a security analysis and further
 * recommendations. In particular, Section 8 of NIST SP 800 38f suggests that the
 * allowed key sizes may be restricted. The implementation in this class
 * requires that the key sizes are in the range MIN_WRAP_KEY_SIZE and MAX_WRAP_KEY_SIZE.
 *
 * <p>The minimum of 16 bytes has been chosen, because 128 bit keys are the smallest
 * key sizes used in tink. Additionally, wrapping short keys with KWP does not use
 * the function W and hence prevents using security arguments based on the assumption
 * that W is strong pseudorandom. (I.e. one consequence of using a strong pseudorandom
 * permutation as an underlying function is that leaking partial information about
 * decrypted bytes is not useful for an attack.)
 *
 * <p>The upper bound for the key size is somewhat arbitrary. Setting an upper bound is
 * motivated by the analysis in section A.4 of NIST SP 800 38f: forgeries of long
 * messages is simpler than forgeries of short message.
 *
 * @since 1.?.?
 */
public class Kwp implements KeyWrap {
  private final SecretKey aesKey;

  static final int MIN_WRAP_KEY_SIZE = 16;
  static final int MAX_WRAP_KEY_SIZE = 4096;
  static final int ROUNDS = 6;
  static final byte[] PREFIX = new byte[]{(byte) 0xa6, (byte) 0x59, (byte) 0x59, (byte) 0xa6};

  /**
   * Construct a new Instance for KWP.
   * @param key the wrapping key. This is an AES key.
   *   Supported key sizes are 128 and 256 bits.
   */
  public Kwp(final byte[] key) throws GeneralSecurityException {
    if (key.length != 16 && key.length != 32) {
      throw new GeneralSecurityException("Unsupported key length");
    }
    aesKey = new SecretKeySpec(key, "AES");
  }

  /**
   * Returns the size of a wrapped key for a given input size.
   * @param inputSize the size of the key to wrap in bytes.
   */
  private int wrappingSize(int inputSize) {
    int paddingSize = 7 - (inputSize + 7) % 8;
    return inputSize + paddingSize + 8;
  }

  /**
   * Computes the pseudorandom permutation W over the IV
   * concatenated with zero padded key material.
   * @param iv an IV of size 8.
   * @param key the key to wrap.
   *            The pseudorandom permutation W is only defined for
   *            inputs with a size that is a multiple of 8 bytes and
   *            that is at least 24 bytes long. Hence computeW is undefined
   *            for keys of size 8 bytes or shorter.
   */
  private byte[] computeW(final byte[] iv, final byte[] key)
      throws GeneralSecurityException {
    // Checks the parameter sizes for which W is defined.
    // Note, that the caller ensures stricter limits.
    if (key.length <= 8 || key.length > Integer.MAX_VALUE - 16 || iv.length != 8) {
      throw new GeneralSecurityException("computeW called with invalid parameters");
    }
    byte[] data = new byte[wrappingSize(key.length)];
    System.arraycopy(iv, 0, data, 0, iv.length);
    System.arraycopy(key, 0, data, 8, key.length); 
    int blocks = data.length / 8 - 1;
    Cipher aes = EngineFactory.CIPHER.getInstance("AES/ECB/NoPadding");
    aes.init(Cipher.ENCRYPT_MODE, aesKey);
    byte[] block = new byte[16];
    System.arraycopy(data, 0, block, 0, 8);
    for (int i = 0; i < ROUNDS; i++) {
      for (int j = 0; j < blocks; j++) {
        System.arraycopy(data, 8 * (j + 1), block, 8, 8);
        int length = aes.doFinal(block, 0, 16, block);
        assert length == 16;
        // xor the round constant in bigendian order to the left half of block. 
        int roundConst = i * blocks + j + 1;
        for (int b = 0; b < 4; b++) {
          block[7 - b] ^= (byte) (roundConst & 0xff);
          roundConst >>>= 8;
        }
        System.arraycopy(block, 8, data, 8 * (j + 1), 8);
      }
    }
    System.arraycopy(block, 0, data, 0, 8);
    return data;
  }

  /**
   * Compute the inverse of the pseudorandom permutation W.
   * @param wrapped the input data to invert. This is the wrapped key.
   * @return the concatenation of the IV followed by a potentially
   *         zero padded key.
   *         invertW does not perform an integrity check.
   */
  private byte[] invertW(final byte[] wrapped) throws GeneralSecurityException {
    // Checks the input size for which invertW is defined.
    // The caller ensures stricter limits
    if (wrapped.length < 24 || wrapped.length % 8 != 0) {
      throw new GeneralSecurityException("Incorrect data size");
    }
    byte[] data = Arrays.copyOf(wrapped, wrapped.length);
    int blocks = data.length / 8 - 1;
    Cipher aes = EngineFactory.CIPHER.getInstance("AES/ECB/NoPadding");
    aes.init(Cipher.DECRYPT_MODE, aesKey);
    byte[] block = new byte[16];
    System.arraycopy(data, 0, block, 0, 8);
    for (int i = ROUNDS - 1; i >= 0; i--) {
      for (int j = blocks - 1; j >= 0; j--) {
        System.arraycopy(data, 8 * (j + 1), block, 8, 8);
        // xor the round constant in bigendian order to the left half of block. 
        int roundConst = i * blocks + j + 1;
        for (int b = 0; b < 4; b++) {
          block[7 - b] ^= (byte) (roundConst & 0xff);
          roundConst >>>= 8;
        }

        int length = aes.doFinal(block, 0, 16, block);
        assert length == 16;
        System.arraycopy(block, 8, data, 8 * (j + 1), 8);
      }
    }
    System.arraycopy(block, 0, data, 0, 8);
    return data;
  }

  /**
   * Wraps some key material {@code data}.
   *
   * @param data the key to wrap. 
   * @return the wrapped key
   */
  @Override
  public byte[] wrap(final byte[] data) throws GeneralSecurityException {
    if (data.length < MIN_WRAP_KEY_SIZE) {
      throw new GeneralSecurityException("Key size of key to wrap too small");
    }
    if (data.length > MAX_WRAP_KEY_SIZE) {
      throw new GeneralSecurityException("Key size of key to wrap too large");
    }
    byte[] iv = new byte[8];
    System.arraycopy(PREFIX, 0, iv, 0, PREFIX.length);
    for (int i = 0; i < 4; i++) {
      iv[4 + i] = (byte) ((data.length >> (8 * (3 - i))) & 0xff);
    }
    return computeW(iv, data);
  }

  /**
   * Unwraps a wrapped key.
   *
   * @throws GeneralSecurityException if {@code data} fails the integrity check.
   */
  @Override
  public byte[] unwrap(final byte[] data) throws GeneralSecurityException {
    if (data.length < wrappingSize(MIN_WRAP_KEY_SIZE)) {
      throw new GeneralSecurityException("Wrapped key size is too small");
    }
    if (data.length > wrappingSize(MAX_WRAP_KEY_SIZE)) {
      throw new GeneralSecurityException("Wrapped key size is too large");
    }
    if (data.length % 8 != 0) {
      throw new GeneralSecurityException(
          "Wrapped key size must be a multiple of 8 bytes");
    }
    byte[] unwrapped = invertW(data);
    // Check the padding.
    // W has been designed to be a strong pseudorandom permutation.
    // Hence leaking any amount of information about improperly padded keys
    // would not be a vulnerability. This means that here we don't have to go to
    // some extra length to assure that the code is constant time. 
    boolean ok = true;
    for (int i = 0; i < 4; i++) {
      if (PREFIX[i] != unwrapped[i]) {
        ok = false;
      }
    }
    int encodedSize = 0;
    for (int i = 4; i < 8; i++) {
      encodedSize = (encodedSize << 8) + (unwrapped[i] & 0xff);
    }
    if (wrappingSize(encodedSize) != unwrapped.length) {
      ok = false;
    } else {
      for (int j = 8 + encodedSize; j < unwrapped.length; j++) {
        if (unwrapped[j] != 0) {
          ok = false;
        }
      }
    }
    if (ok) {
      return Arrays.copyOfRange(unwrapped, 8, 8 + encodedSize);
    } else {
      throw new BadPaddingException("Invalid padding");
    }
  }
}
