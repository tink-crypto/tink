// Copyright 2021 Google LLC
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

package com.google.crypto.tink.aead.internal;

import java.security.InvalidKeyException;

/**
 * A stream cipher, as described in RFC 8439 https://tools.ietf.org/html/rfc8439, section 2.4.
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
 */
public class InsecureNonceChaCha20 extends InsecureNonceChaCha20Base {
  public InsecureNonceChaCha20(final byte[] key, int initialCounter) throws InvalidKeyException {
    super(key, initialCounter);
  }

  @Override
  public int[] createInitialState(final int[] nonce, int counter) {
    if (nonce.length != nonceSizeInBytes() / 4) {
      throw new IllegalArgumentException(
          String.format("ChaCha20 uses 96-bit nonces, but got a %d-bit nonce", nonce.length * 32));
    }
    // Set the initial state based on https://tools.ietf.org/html/rfc8439#section-2.3
    int[] state = new int[ChaCha20Util.BLOCK_SIZE_IN_INTS];
    // The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
    // The next eight words (4-11) are taken from the 256-bit key by reading the bytes in
    // little-endian order, in 4-byte chunks.
    ChaCha20Util.setSigmaAndKey(state, this.key);
    // Word 12 is a block counter. Since each block is 64-byte, a 32-bit word is enough for 256
    // gigabytes of data. Ref: https://tools.ietf.org/html/rfc8439#section-2.3.
    state[12] = counter;
    // Words 13-15 are a nonce, which must not be repeated for the same key. The 13th word is the
    // first 32 bits of the input nonce taken as a little-endian integer, while the 15th word is the
    // last 32 bits.
    System.arraycopy(nonce, 0, state, 13, nonce.length);
    return state;
  }

  @Override
  public int nonceSizeInBytes() {
    return 12;
  }
}
