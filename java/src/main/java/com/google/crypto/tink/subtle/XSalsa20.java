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
 * DJB's XSalsa20 stream cipher.
 * https://cr.yp.to/snuffle/xsalsa-20081128.pdf
 */
public class XSalsa20 extends DJBCipher {

  /**
   * Constructs a new {@link XSalsa20} cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not
   * {@link DJBCipher#KEY_SIZE_IN_BYTES}.
   */
  public XSalsa20(byte[] key) {
    super(key);
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

  @Override
  void shuffle(final int[] state) {
    for (int i = 0; i < 10; i++) {
      columnRound(state);
      rowRound(state);
    }
  }

  @Override
  int[] initialState(byte[] nonce, int counter) {
    // Set the initial state based on https://cr.yp.to/snuffle/xsalsa-20081128.pdf
    int[] state = new int[BLOCK_SIZE_IN_INTS];
    state[0] = SIGMA[0];
    state[5] = SIGMA[1];
    state[10] = SIGMA[2];
    state[15] = SIGMA[3];
    int[] keyInt = toIntArray(ByteBuffer.wrap(key));
    state[1] = keyInt[0];
    state[2] = keyInt[1];
    state[3] = keyInt[2];
    state[4] = keyInt[3];
    state[11] = keyInt[4];
    state[12] = keyInt[5];
    state[13] = keyInt[6];
    state[14] = keyInt[7];
    int[] nonceInt = toIntArray(ByteBuffer.wrap(nonce));
    state[6] = nonceInt[0];
    state[7] = nonceInt[1];
    state[8] = nonceInt[2];
    state[9] = nonceInt[3];
    shuffle(state);
    state[1] = state[0];
    state[2] = state[5];
    state[3] = state[10];
    state[4] = state[15];
    state[11] = state[6];
    state[12] = state[7];
    state[13] = state[8];
    state[14] = state[9];
    state[0] = SIGMA[0];
    state[5] = SIGMA[1];
    state[10] = SIGMA[2];
    state[15] = SIGMA[3];
    state[6] = nonceInt[4];
    state[7] = nonceInt[5];
    state[8] = counter;
    state[9] = 0;
    return state;
  }

  @Override
  void incrementCounter(int[] state) {
    state[8]++;
    if (state[8] == 0) {
      state[9]++;
    }
  }

  @Override
  int nonceSizeInBytes() {
    return 24;
  }
}
