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
import java.util.Arrays;

/**
 * DJB's ChaCha20 stream cipher based on RFC7539.
 * https://tools.ietf.org/html/rfc7539
 */
public class ChaCha20 implements IndCpaCipher {

  private static final int BLOCK_INT_SIZE = 16;
  public static final int BLOCK_BYTE_SIZE = BLOCK_INT_SIZE * 4;
  private static final int NONCE_INT_SIZE = 3;
  public static final int NONCE_BYTE_SIZE = NONCE_INT_SIZE * 4;
  private static final int KEY_INT_SIZE = 8;
  public static final int KEY_BYTE_SIZE = KEY_INT_SIZE * 4;

  private static final int[] SIGMA = toIntArray(ByteBuffer.wrap(
      new byte[]{'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k' }));
  private static final int COUNTER_POS = SIGMA.length + KEY_INT_SIZE;

  // TODO(anergiz): change this to ImmutableByteArray.
  private final byte[] key;

  /**
   * Constructs a new ChaCha20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link ChaCha20#KEY_BYTE_SIZE}.
   */
  public ChaCha20(byte[] key) {
    if (key.length != KEY_BYTE_SIZE) {
      throw new IllegalArgumentException("The key length in bytes must be 32.");
    }
    this.key = key;
  }

  private static int rotateLeft(int x, int y) {
    return (x << y) | (x >>> -y);
  }

  private static int[] toIntArray(ByteBuffer in) {
    IntBuffer intBuffer = in.order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
    int[] ret = new int[intBuffer.remaining()];
    intBuffer.get(ret);
    return ret;
  }

  static void quarterRound(int[] x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotateLeft(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotateLeft(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotateLeft(x[d] ^ x[a],  8);
    x[c] += x[d]; x[b] = rotateLeft(x[b] ^ x[c],  7);
  }

  static void chaChaCore(ByteBuffer output, final int[] input) {
    int[] x = Arrays.copyOf(input, input.length);
    for (int i = 0; i < 10; i++) {
      quarterRound(x, 0, 4, 8, 12);
      quarterRound(x, 1, 5, 9, 13);
      quarterRound(x, 2, 6, 10, 14);
      quarterRound(x, 3, 7, 11, 15);
      quarterRound(x, 0, 5, 10, 15);
      quarterRound(x, 1, 6, 11, 12);
      quarterRound(x, 2, 7, 8, 13);
      quarterRound(x, 3, 4, 9, 14);
    }
    for (int i = 0; i < x.length; i++) {
      x[i] += input[i];
    }
    output.asIntBuffer().put(x);
  }

  void update(ByteBuffer output, final byte[] input, int inPos, byte[] nonce, int counter) {
    // Set the initial state based on https://tools.ietf.org/html/rfc7539#section-2.3
    int[] state = new int[BLOCK_INT_SIZE];
    int pos = 0;
    System.arraycopy(SIGMA, 0, state, pos, SIGMA.length);
    pos += SIGMA.length;
    System.arraycopy(toIntArray(ByteBuffer.wrap(key)), 0, state, pos, KEY_INT_SIZE);
    state[COUNTER_POS] = counter;
    pos += KEY_INT_SIZE + 1;  // additional one for counter
    System.arraycopy(toIntArray(ByteBuffer.wrap(nonce)), 0, state, pos, NONCE_INT_SIZE);

    // Do the ChaCha20 operation on the input.
    ByteBuffer buf = ByteBuffer.allocate(BLOCK_BYTE_SIZE).order(ByteOrder.LITTLE_ENDIAN);
    pos = inPos;
    int inLen = input.length - inPos;
    int todo;
    while (inLen > 0) {
      todo = inLen < BLOCK_BYTE_SIZE ? inLen : BLOCK_BYTE_SIZE;
      chaChaCore(buf, state);
      for (int j = 0; j < todo; j++, pos++) {
        output.put((byte) (input[pos] ^ buf.array()[j]));
      }
      inLen -= todo;
      state[COUNTER_POS]++;
    }
  }

  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - NONCE_BYTE_SIZE) {
      throw new GeneralSecurityException("plaintext too long");
    }
    byte[] nonce = Random.randBytes(NONCE_BYTE_SIZE);
    ByteBuffer ciphertext = ByteBuffer.allocate(plaintext.length + NONCE_BYTE_SIZE);
    ciphertext.put(nonce);
    update(ciphertext, plaintext, 0, nonce, 1);
    return ciphertext.array();
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext) throws GeneralSecurityException {
    if (ciphertext.length < NONCE_BYTE_SIZE) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] nonce = new byte[NONCE_BYTE_SIZE];
    System.arraycopy(ciphertext, 0, nonce, 0, NONCE_BYTE_SIZE);
    ByteBuffer plaintext = ByteBuffer.allocate(ciphertext.length - NONCE_BYTE_SIZE);
    update(plaintext, ciphertext, NONCE_BYTE_SIZE, nonce, 1);
    return plaintext.array();
  }
}
