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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * Abstract base class for ChaCha20 and XChaCha20.
 *
 * <p>ChaCha20 and XChaCha20 have two differences: the size of the nonce and the initial state of
 * the block function that produces a key stream block from a key, a nonce, and a counter.
 *
 * <p>Concrete implementations of this class are meant to be used to construct an {@link
 * com.google.crypto.tink.Aead} with {@link com.google.crypto.tink.subtle.Poly1305}.
 *
 * @deprecated replaced by {@link com.google.crypto.tink.aead.internal.ChaCha20Util} and {@link
 *     com.google.crypto.tink.aead.internal.InsecureNonceChaCha20Base}.
 */
@Deprecated
abstract class ChaCha20Base implements IndCpaCipher {
  public static final int BLOCK_SIZE_IN_INTS = 16;
  public static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
  public static final int KEY_SIZE_IN_INTS = 8;
  public static final int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;
  private static final int[] SIGMA =
      toIntArray(
          new byte[] {
            'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
          });
  int[] key;
  private final int initialCounter;

  ChaCha20Base(final byte[] key, int initialCounter) throws InvalidKeyException {
    if (key.length != KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException("The key length in bytes must be 32.");
    }
    this.key = toIntArray(key);
    this.initialCounter = initialCounter;
  }

  /** Returns the initial state from {@code nonce} and {@code counter}. */
  abstract int[] createInitialState(final int[] nonce, int counter);

  /**
   * The size of the randomly generated nonces.
   *
   * <p>ChaCha20 uses 12-byte nonces, but XChaCha20 use 24-byte nonces.
   */
  abstract int nonceSizeInBytes();

  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - nonceSizeInBytes()) {
      throw new GeneralSecurityException("plaintext too long");
    }
    ByteBuffer ciphertext = ByteBuffer.allocate(nonceSizeInBytes() + plaintext.length);
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
      ByteBuffer keyStreamBlock = chacha20Block(nonce, i + initialCounter);
      if (i == numBlocks - 1) {
        // last block
        Bytes.xor(output, input, keyStreamBlock, length % BLOCK_SIZE_IN_BYTES);
      } else {
        Bytes.xor(output, input, keyStreamBlock, BLOCK_SIZE_IN_BYTES);
      }
    }
  }

  // https://tools.ietf.org/html/rfc8439#section-2.3.
  ByteBuffer chacha20Block(final byte[] nonce, int counter) {
    int[] state = createInitialState(toIntArray(nonce), counter);
    int[] workingState = state.clone();
    shuffleState(workingState);
    for (int i = 0; i < state.length; i++) {
      state[i] += workingState[i];
    }
    ByteBuffer out = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES).order(ByteOrder.LITTLE_ENDIAN);
    out.asIntBuffer().put(state, 0, BLOCK_SIZE_IN_INTS);
    return out;
  }

  static void setSigmaAndKey(int[] state, final int[] key) {
    System.arraycopy(SIGMA, 0, state, 0, SIGMA.length);
    System.arraycopy(key, 0, state, SIGMA.length, KEY_SIZE_IN_INTS);
  }

  static void shuffleState(final int[] state) {
    for (int i = 0; i < 10; i++) {
      quarterRound(state, 0, 4, 8, 12);
      quarterRound(state, 1, 5, 9, 13);
      quarterRound(state, 2, 6, 10, 14);
      quarterRound(state, 3, 7, 11, 15);
      quarterRound(state, 0, 5, 10, 15);
      quarterRound(state, 1, 6, 11, 12);
      quarterRound(state, 2, 7, 8, 13);
      quarterRound(state, 3, 4, 9, 14);
    }
  }

  static void quarterRound(int[] x, int a, int b, int c, int d) {
    x[a] += x[b];
    x[d] = rotateLeft(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = rotateLeft(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = rotateLeft(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = rotateLeft(x[b] ^ x[c], 7);
  }

  static int[] toIntArray(final byte[] input) {
    IntBuffer intBuffer = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
    int[] ret = new int[intBuffer.remaining()];
    intBuffer.get(ret);
    return ret;
  }

  private static int rotateLeft(int x, int y) {
    return (x << y) | (x >>> -y);
  }
}
