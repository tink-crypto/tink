// Copyright 2017 Google Inc. //
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
import java.security.InvalidKeyException;

/**
 * XSalsa20 stream cipher, see https://cr.yp.to/snuffle/xsalsa-20081128.pdf.
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
 */
@Alpha
class XSalsa20 extends Snuffle {
  private static final byte[] ZERO_16_BYTES = new byte[16];

  /**
   * Constructs a new {@link XSalsa20} cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     Snuffle#KEY_SIZE_IN_BYTES}.
   */
  XSalsa20(final byte[] key, int initialCounter) throws InvalidKeyException {
    super(key, initialCounter);
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

  @Override
  int nonceSizeInBytes() {
    return 24;
  }

  private int[] createInitialState(final byte[] nonce, int counter) {
    // Set the initial state based on https://cr.yp.to/snuffle/xsalsa-20081128.pdf
    int[] state = new int[BLOCK_SIZE_IN_INTS];
    setSigma(state);
    setKey(state, hSalsa20(key.getBytes(), nonce));
    int[] nonceInt = toIntArray(ByteBuffer.wrap(nonce));
    state[6] = nonceInt[4];
    state[7] = nonceInt[5];
    state[8] = counter;
    state[9] = 0;
    return state;
  }

  static void quarterRound(int[] x, int a, int b, int c, int d) {
    x[b] ^= rotateLeft(x[a] + x[d], 7);
    x[c] ^= rotateLeft(x[b] + x[a], 9);
    x[d] ^= rotateLeft(x[c] + x[b], 13);
    x[a] ^= rotateLeft(x[d] + x[c], 18);
  }

  static void columnRound(final int[] state) {
    quarterRound(state, 0, 4, 8, 12);
    quarterRound(state, 5, 9, 13, 1);
    quarterRound(state, 10, 14, 2, 6);
    quarterRound(state, 15, 3, 7, 11);
  }

  static void rowRound(final int[] state) {
    quarterRound(state, 0, 1, 2, 3);
    quarterRound(state, 5, 6, 7, 4);
    quarterRound(state, 10, 11, 8, 9);
    quarterRound(state, 15, 12, 13, 14);
  }

  private static void shuffleState(final int[] state) {
    for (int i = 0; i < 10; i++) {
      columnRound(state);
      rowRound(state);
    }
  }

  private static void setSigma(int[] state) {
    state[0] = SIGMA[0];
    state[5] = SIGMA[1];
    state[10] = SIGMA[2];
    state[15] = SIGMA[3];
  }

  private static void setKey(int[] state, final byte[] key) {
    int[] keyInt = toIntArray(ByteBuffer.wrap(key));
    System.arraycopy(keyInt, 0, state, 1, 4);
    System.arraycopy(keyInt, 4, state, 11, 4);
  }

  static byte[] hSalsa20(final byte[] key) {
    return hSalsa20(key, ZERO_16_BYTES);
  }

  static byte[] hSalsa20(final byte[] key, final byte[] nonce) {
    int[] state = new int[BLOCK_SIZE_IN_INTS];
    setSigma(state);
    setKey(state, key);
    int[] nonceInt = toIntArray(ByteBuffer.wrap(nonce));
    state[6] = nonceInt[0];
    state[7] = nonceInt[1];
    state[8] = nonceInt[2];
    state[9] = nonceInt[3];
    shuffleState(state);
    // state[0] = state[0]
    state[1] = state[5];
    state[2] = state[10];
    state[3] = state[15];
    state[4] = state[6];
    state[5] = state[7];
    state[6] = state[8];
    state[7] = state[9];
    ByteBuffer buf = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
    buf.asIntBuffer().put(state, 0, 8);
    return buf.array();
  }
}
