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

/**
 * Djb's {@link ChaCha20} stream cipher based on RFC7539 (i.e., uses 96-bit random nonces).
 * https://tools.ietf.org/html/rfc7539
 *
 * This cipher is meant to be used to construct an AEAD with Poly1305.
 */
public class ChaCha20 extends DjbCipher {

  public static final int NONCE_SIZE_IN_BYTES = 12;
  private static final int COUNTER_POS = SIGMA.length + KEY_SIZE_IN_INTS;

  /**
   * Constructs a new ChaCha20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not
   * {@link DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  public ChaCha20(final byte[] key) {
    super(key);
  }

  static void quarterRound(int[] x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotateLeft(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotateLeft(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotateLeft(x[d] ^ x[a],  8);
    x[c] += x[d]; x[b] = rotateLeft(x[b] ^ x[c],  7);
  }

  @Override
  void shuffle(final int[] state) {
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

  @Override
  int[] initialState(final byte[] nonce, int counter) {
    // Set the initial state based on https://tools.ietf.org/html/rfc7539#section-2.3
    int[] state = new int[BLOCK_SIZE_IN_INTS];
    int pos = 0;
    System.arraycopy(SIGMA, 0, state, pos, SIGMA.length);
    pos += SIGMA.length;
    System.arraycopy(toIntArray(ByteBuffer.wrap(key)), 0, state, pos, KEY_SIZE_IN_INTS);
    state[COUNTER_POS] = counter;
    pos += KEY_SIZE_IN_INTS + 1;  // additional one for counter
    System.arraycopy(toIntArray(ByteBuffer.wrap(nonce)), 0, state, pos, nonceSizeInBytes() / 4);
    return state;
  }

  @Override
  void incrementCounter(int[] state) {
    state[COUNTER_POS]++;
  }

  @Override
  int nonceSizeInBytes() {
    return NONCE_SIZE_IN_BYTES;
  }

  @Override
  KeyStream getKeyStream(byte[] nonce) {
    return new KeyStream(this, nonce, 1);
  }
}
