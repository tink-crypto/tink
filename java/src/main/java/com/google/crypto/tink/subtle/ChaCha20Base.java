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

/** Base class for {@link ChaCha20} and {@link XChaCha20}. */
@Alpha
abstract class ChaCha20Base extends SnuffleCipher {

  ChaCha20Base(final byte[] key) {
    super(key);
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

  static void shuffleInternal(final int[] state) {
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
  void shuffle(final int[] state) {
    shuffleInternal(state);
  }

  static void setSigma(int[] state) {
    System.arraycopy(SnuffleCipher.SIGMA, 0, state, 0, SIGMA.length);
  }

  static void setKey(int[] state, final byte[] key) {
    int[] keyInt = toIntArray(ByteBuffer.wrap(key));
    System.arraycopy(keyInt, 0, state, 4, keyInt.length);
  }

  static byte[] hChaCha20(final byte[] key) {
    return hChaCha20(key, SnuffleCipher.ZERO_16_BYTES);
  }

  static byte[] hChaCha20(final byte[] key, final byte[] nonce) {
    int[] state = new int[SnuffleCipher.BLOCK_SIZE_IN_INTS];
    setSigma(state);
    setKey(state, key);
    int[] nonceInt = toIntArray(ByteBuffer.wrap(nonce));
    state[12] = nonceInt[0];
    state[13] = nonceInt[1];
    state[14] = nonceInt[2];
    state[15] = nonceInt[3];
    shuffleInternal(state);
    // state[0] = state[0], state[1] = state[1], state[2] = state[2], state[3] = state[3]
    state[4] = state[12];
    state[5] = state[13];
    state[6] = state[14];
    state[7] = state[15];
    ByteBuffer buf = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
    buf.asIntBuffer().put(state, 0, 8);
    return buf.array();
  }
}
