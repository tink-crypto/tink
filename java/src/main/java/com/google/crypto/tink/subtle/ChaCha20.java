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
import java.security.InvalidKeyException;

/**
 * A stream cipher based on RFC7539 (i.e., uses 96-bit random nonces).
 * https://tools.ietf.org/html/rfc7539
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
 */
@Alpha
class ChaCha20 extends ChaCha20Base {
  ChaCha20(final byte[] key, int initialCounter) throws InvalidKeyException {
    super(key, initialCounter);
  }

  @Override
  int[] createInitialState(final byte[] nonce, int counter) {
    // Set the initial state based on https://tools.ietf.org/html/rfc7539#section-2.3
    int[] state = new int[Snuffle.BLOCK_SIZE_IN_INTS];
    ChaCha20Base.setSigma(state);
    ChaCha20Base.setKey(state, key.getBytes());
    state[12] = counter;
    System.arraycopy(toIntArray(ByteBuffer.wrap(nonce)), 0, state, 13, nonceSizeInBytes() / 4);
    return state;
  }

  @Override
  int nonceSizeInBytes() {
    return 12;
  }
}
