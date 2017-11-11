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
 * {@link XChaCha20} stream cipher based on
 * https://download.libsodium.org/doc/advanced/xchacha20.html
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
 */
@Alpha
class XChaCha20 extends ChaCha20Base {

  /**
   * Constructs a new XChaCha20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     Snuffle#KEY_SIZE_IN_BYTES}.
   */
  XChaCha20(byte[] key, int initialCounter) throws InvalidKeyException {
    super(key, initialCounter);
  }

  @Override
  int[] createInitialState(final byte[] nonce, int counter) {
    // Set the initial state based on https://cr.yp.to/snuffle/xsalsa-20081128.pdf
    int[] state = new int[Snuffle.BLOCK_SIZE_IN_INTS];
    ChaCha20Base.setSigma(state);
    ChaCha20Base.setKey(state, hChaCha20(key.getBytes(), nonce));
    int[] nonceInt = toIntArray(ByteBuffer.wrap(nonce));
    state[14] = nonceInt[4];
    state[15] = nonceInt[5];
    state[12] = counter;
    state[13] = 0;
    return state;
  }

  @Override
  int nonceSizeInBytes() {
    return 24;
  }
}
