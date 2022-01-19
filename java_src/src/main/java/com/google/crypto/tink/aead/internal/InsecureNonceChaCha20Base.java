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

import com.google.crypto.tink.subtle.Bytes;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * Abstract base class for {@link InsecureNonceChaCha20}.
 *
 * <p>ChaCha20 and XChaCha20 have two differences: the size of the nonce and the initial state of
 * the block function that produces a key stream block from a key, a nonce, and a counter.
 *
 * <p>Concrete implementations of this class are meant to be used to construct an {@link
 * com.google.crypto.tink.Aead} with {@link com.google.crypto.tink.subtle.Poly1305}.
 *
 * <p>Since this class supports user-supplied nonces, which would be insecure if the nonce ever
 * repeates, most users should not use this class directly.
 */
abstract class InsecureNonceChaCha20Base {
  int[] key;
  private final int initialCounter;

  public InsecureNonceChaCha20Base(final byte[] key, int initialCounter)
      throws InvalidKeyException {
    if (key.length != ChaCha20Util.KEY_SIZE_IN_BYTES) {
      throw new InvalidKeyException("The key length in bytes must be 32.");
    }
    this.key = ChaCha20Util.toIntArray(key);
    this.initialCounter = initialCounter;
  }

  /** Returns the initial state from {@code nonce} and {@code counter}. */
  abstract int[] createInitialState(final int[] nonce, int counter);

  /**
   * The size of the randomly generated nonces.
   *
   * <p>ChaCha20 uses 12-byte nonces, but XChaCha20 use 24-byte nonces.
   */
  abstract int nonceSizeInBytes();

  /** Encrypts {@code plaintext} using {@code nonce}. */
  public byte[] encrypt(final byte[] nonce, final byte[] plaintext)
      throws GeneralSecurityException {
    ByteBuffer ciphertext = ByteBuffer.allocate(plaintext.length);
    encrypt(ciphertext, nonce, plaintext);
    return ciphertext.array();
  }

  /** Encrypts {@code plaintext} using {@code nonce} and writes result to {@code output}. */
  public void encrypt(ByteBuffer output, final byte[] nonce, final byte[] plaintext)
      throws GeneralSecurityException {
    if (output.remaining() < plaintext.length) {
      throw new IllegalArgumentException("Given ByteBuffer output is too small");
    }
    process(nonce, output, ByteBuffer.wrap(plaintext));
  }

  /** Decrypts {@code ciphertext} using {@code nonce}. */
  public byte[] decrypt(final byte[] nonce, final byte[] ciphertext)
      throws GeneralSecurityException {
    return decrypt(nonce, ByteBuffer.wrap(ciphertext));
  }

  /** Decrypts {@code ciphertext} using {@code nonce}. */
  public byte[] decrypt(final byte[] nonce, ByteBuffer ciphertext) throws GeneralSecurityException {
    ByteBuffer plaintext = ByteBuffer.allocate(ciphertext.remaining());
    process(nonce, plaintext, ciphertext);
    return plaintext.array();
  }

  private void process(final byte[] nonce, ByteBuffer output, ByteBuffer input)
      throws GeneralSecurityException {
    if (nonce.length != nonceSizeInBytes()) {
      throw new GeneralSecurityException(
          "The nonce length (in bytes) must be " + nonceSizeInBytes());
    }
    int length = input.remaining();
    int numBlocks = (length / ChaCha20Util.BLOCK_SIZE_IN_BYTES) + 1;
    for (int i = 0; i < numBlocks; i++) {
      ByteBuffer keyStreamBlock = chacha20Block(nonce, i + initialCounter);
      if (i == numBlocks - 1) {
        // last block
        Bytes.xor(output, input, keyStreamBlock, length % ChaCha20Util.BLOCK_SIZE_IN_BYTES);
      } else {
        Bytes.xor(output, input, keyStreamBlock, ChaCha20Util.BLOCK_SIZE_IN_BYTES);
      }
    }
  }

  // https://tools.ietf.org/html/rfc8439#section-2.3.
  ByteBuffer chacha20Block(final byte[] nonce, int counter) {
    int[] state = createInitialState(ChaCha20Util.toIntArray(nonce), counter);
    int[] workingState = state.clone();
    ChaCha20Util.shuffleState(workingState);
    for (int i = 0; i < state.length; i++) {
      state[i] += workingState[i];
    }
    ByteBuffer out =
        ByteBuffer.allocate(ChaCha20Util.BLOCK_SIZE_IN_BYTES).order(ByteOrder.LITTLE_ENDIAN);
    out.asIntBuffer().put(state, 0, ChaCha20Util.BLOCK_SIZE_IN_INTS);
    return out;
  }
}
