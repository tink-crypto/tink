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
import java.security.InvalidKeyException;

/**
 * A stream cipher based on RFC7539 (i.e., uses 96-bit random nonces)
 * https://tools.ietf.org/html/rfc7539
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
 */
class ChaCha20 extends Snuffle {
  private static final byte[] ZERO_16_BYTES = new byte[16];

  ChaCha20(final byte[] key, int initialCounter) throws InvalidKeyException {
    super(key, initialCounter);
  }

  /**
   * Returns the initial state from {@code nonce} and {@code counter}.
   *
   * <p>ChaCha20 has a different logic than XChaCha20, because the former uses a 12-byte nonce, but
   * the later uses 24-byte.
   */
  private int[] createInitialState(final byte[] nonce, int counter) {
    // Set the initial state based on https://tools.ietf.org/html/rfc7539#section-2.3
    int[] state = new int[Snuffle.BLOCK_SIZE_IN_INTS];
    setSigma(state);
    setKey(state, key.getBytes());
    state[12] = counter;
    System.arraycopy(toIntArray(ByteBuffer.wrap(nonce)), 0, state, 13, nonceSizeInBytes() / 4);
    return state;
  }

  @Override
  int nonceSizeInBytes() {
    return 12;
  }

  @Override
  ByteBuffer getKeyStreamBlock(final byte[] nonce, int counter) {
    int[] state = createInitialState(nonce, counter);
    int[] workingState = state.clone();
    shuffleState(workingState);
    for (int i = 0; i < state.length; i++) {
      state[i] += workingState[i];
    }
    ByteBuffer out = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES).order(ByteOrder.LITTLE_ENDIAN);
    out.asIntBuffer().put(state, 0, BLOCK_SIZE_IN_INTS);
    return out;
  }

  private static void setSigma(int[] state) {
    System.arraycopy(Snuffle.SIGMA, 0, state, 0, SIGMA.length);
  }

  private static void setKey(int[] state, final byte[] key) {
    int[] keyInt = toIntArray(ByteBuffer.wrap(key));
    System.arraycopy(keyInt, 0, state, 4, keyInt.length);
  }

  private static void shuffleState(final int[] state) {
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
}
