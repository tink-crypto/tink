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

import com.google.crypto.tink.annotations.Alpha;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * Abstract base class for class of XSalsa20, ChaCha20, XChaCha20 and their variants.
 *
 * <p>Variants of Snuffle have two differences: the size of the nonce and the block function that
 * produces a key stream block from a key, a nonce, and a counter. Subclasses of this class
 * specifying these two information by overriding {@link #nonceSizeInBytes} and
 * {@link #getKeyStreamBlock}.
 *
 * <p>Concrete implementations of this class are meant to be used to construct an
 * {@link com.google.crypto.tink.Aead} with {@link com.google.crypto.tink.subtle.Poly1305}. The
 * base class of these Aead constructions is {@link com.google.crypto.tink.subtle.SnufflePoly1305}.
 * For example, {@link com.google.crypto.tink.subtle.XSalsa20} is a subclass of this class and a
 * concrete Snuffle implementation, and {@link com.google.crypto.tink.subtle.XSalsa20Poly1305} is
 * a subclass of {@link com.google.crypto.tink.subtle.SnufflePoly1305} and a concrete Aead
 * construction.
 */
@Alpha
abstract class Snuffle implements IndCpaCipher {
  public static final int BLOCK_SIZE_IN_INTS = 16;
  public static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
  public static final int KEY_SIZE_IN_INTS = 8;
  public static final int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;
  static final int[] SIGMA =
      toIntArray(
          ByteBuffer.wrap(
              new byte[] {
                'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
              }));

  final ImmutableByteArray key;
  private final int initialCounter;

  /**
   * Returns a key stream block from {@code nonce} and {@code counter}.
   *
   * <p>From this function, the Snuffle encryption function can be constructed using the counter
   * mode of operation. For example, the ChaCha20 block function and how it can be used to
   * construct the ChaCha20 encryption function are described in section 2.3 and 2.4 of RFC 7539.
   */
  abstract ByteBuffer getKeyStreamBlock(final byte[] nonce, int counter);

  /**
   * The size of the randomly generated nonces.
   *
   * <p>ChaCha20 uses 12-byte nonces, but XSalsa20 and XChaCha20 use 24-byte nonces.
   */
  abstract int nonceSizeInBytes();

  Snuffle(final byte[] key, int initialCounter) throws InvalidKeyException {
    if (key.length != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException("The key length in bytes must be 32.");
    }
    this.key = ImmutableByteArray.of(key);
    this.initialCounter = initialCounter;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - nonceSizeInBytes()) {
      throw new GeneralSecurityException("plaintext too long");
    }
    ByteBuffer ciphertext = ByteBuffer.allocate(
        nonceSizeInBytes() + plaintext.length);
    encrypt(ciphertext, plaintext);
    return ciphertext.array();
  }

  void encrypt(ByteBuffer output, final byte[] plaintext) throws GeneralSecurityException {
    if (output.remaining() - nonceSizeInBytes() < plaintext.length) {
      throw new IllegalArgumentException("Given ByteBuffer output is too small");
    }

    byte[] nonce = Random.randBytes(nonceSizeInBytes());
    output.put(nonce);
    process(nonce, output, ByteBuffer.wrap(plaintext));
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext) throws GeneralSecurityException {
    return decrypt(ByteBuffer.wrap(ciphertext));
  }

  byte[] decrypt(ByteBuffer ciphertext) throws GeneralSecurityException {
    if (ciphertext.remaining() < nonceSizeInBytes()) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] nonce = new byte[nonceSizeInBytes()];
    ciphertext.get(nonce);
    ByteBuffer plaintext = ByteBuffer.allocate(ciphertext.remaining());
    process(nonce, plaintext, ciphertext);
    return plaintext.array();
  }

  private void process(final byte[] nonce, ByteBuffer output, ByteBuffer input)
      throws GeneralSecurityException {
    int length = input.remaining();
    int numBlocks = (length / BLOCK_SIZE_IN_BYTES) + 1;
    for (int i = 0; i < numBlocks; i++) {
      ByteBuffer keyStreamBlock = getKeyStreamBlock(nonce, i + initialCounter);
      if (i == numBlocks - 1) {
        // last block
        Bytes.xor(
            output,
            input,
            keyStreamBlock,
            length % BLOCK_SIZE_IN_BYTES);
      } else {
        Bytes.xor(
            output,
            input,
            keyStreamBlock,
            BLOCK_SIZE_IN_BYTES);
      }
    }
  }

  static int rotateLeft(int x, int y) {
    return (x << y) | (x >>> -y);
  }

  static int[] toIntArray(ByteBuffer in) {
    IntBuffer intBuffer = in.order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
    int[] ret = new int[intBuffer.remaining()];
    intBuffer.get(ret);
    return ret;
  }
}
