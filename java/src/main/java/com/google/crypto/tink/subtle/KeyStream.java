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

/**
 * State generator for SnuffleCipher types. Stateful and <b>not</b> thread-safe. {@link KeyStream}
 * is not stored as an instance variable in {@link SnuffleCipher} types to preserve their stateless
 * guarantee. Instead, it is used in local scope to easily maintain the local state inside of a
 * single call (i.e., encrypt or decrypt).
 */
class KeyStream {

  private SnuffleCipher snuffleCipher;
  private int[] state;
  private int[] keyStreamBlock;
  // The blocks that is returned, can be unaligned from the actual key stream blocks if first is
  // called before next.
  private int[] keyStreamBlockReturn;
  private int currentPosInBlock;
  private boolean readCalled;

  KeyStream(SnuffleCipher snuffleCipher, final byte[] nonce, int counter) {
    this.snuffleCipher = snuffleCipher;
    keyStreamBlockReturn = new int[SnuffleCipher.BLOCK_SIZE_IN_INTS];
    currentPosInBlock = 0;
    state = snuffleCipher.initialState(nonce, counter);
    keyStreamBlock = snuffleCipher.shuffleAdd(state);
    readCalled = false;
  }

  byte[] first(int byteLength) {
    if (readCalled) {
      throw new IllegalStateException("first can only be called once and before next().");
    }
    if (byteLength >= SnuffleCipher.BLOCK_SIZE_IN_BYTES) {
      throw new IllegalArgumentException(
          String.format("length must be less than 64. length: %d", byteLength));
    }
    if (byteLength % 4 != 0) {
      throw new IllegalArgumentException(
          String.format("length must be a multiple of 4. length: %d", byteLength));
    }
    readCalled = true;
    currentPosInBlock = byteLength / 4;
    ByteBuffer out = ByteBuffer.allocate(byteLength).order(ByteOrder.LITTLE_ENDIAN);
    out.asIntBuffer().put(keyStreamBlock, 0, byteLength / 4);
    return out.array();
  }

  int[] next() {
    readCalled = true;
    System.arraycopy(
        keyStreamBlock,
        currentPosInBlock,
        keyStreamBlockReturn,
        0,
        SnuffleCipher.BLOCK_SIZE_IN_INTS - currentPosInBlock);
    snuffleCipher.incrementCounter(state);
    keyStreamBlock = snuffleCipher.shuffleAdd(state);
    System.arraycopy(
        keyStreamBlock,
        0,
        keyStreamBlockReturn,
        SnuffleCipher.BLOCK_SIZE_IN_INTS - currentPosInBlock,
        currentPosInBlock);
    return keyStreamBlockReturn;
  }
}
