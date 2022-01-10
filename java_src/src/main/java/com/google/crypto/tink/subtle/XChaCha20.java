// Copyright 2018 Google Inc.
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

import com.google.crypto.tink.aead.internal.InsecureNonceXChaCha20;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * {@link XChaCha20} stream cipher based on
 * https://download.libsodium.org/doc/advanced/xchacha20.html and
 * https://tools.ietf.org/html/draft-arciszewski-xchacha-01.
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
 */
class XChaCha20 implements IndCpaCipher {
  static final int NONCE_LENGTH_IN_BYTES = 24;

  private final InsecureNonceXChaCha20 cipher;

  /**
   * Constructs a new XChaCha20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     com.google.crypto.tink.aead.internal.ChaCha20Util#KEY_SIZE_IN_BYTES}.
   */
  XChaCha20(byte[] key, int initialCounter) throws InvalidKeyException {
    cipher = new InsecureNonceXChaCha20(key, initialCounter);
  }

  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    ByteBuffer output = ByteBuffer.allocate(NONCE_LENGTH_IN_BYTES + plaintext.length);
    byte[] nonce = Random.randBytes(NONCE_LENGTH_IN_BYTES);
    output.put(nonce); // Prepend nonce to ciphertext output.
    cipher.encrypt(output, nonce, plaintext);
    return output.array();
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext) throws GeneralSecurityException {
    if (ciphertext.length < NONCE_LENGTH_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] nonce = Arrays.copyOf(ciphertext, NONCE_LENGTH_IN_BYTES);
    ByteBuffer rawCiphertext =
        ByteBuffer.wrap(
            ciphertext, NONCE_LENGTH_IN_BYTES, ciphertext.length - NONCE_LENGTH_IN_BYTES);
    return cipher.decrypt(nonce, rawCiphertext);
  }
}
