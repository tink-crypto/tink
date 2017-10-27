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

import static com.google.crypto.tink.subtle.Poly1305.MAC_KEY_SIZE_IN_BYTES;

import com.google.crypto.tink.annotations.Alpha;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Abstract base class for class of Snuffle 2005 and Snuffle 2008 ciphers and their variants.
 *
 * <p>Class of Snuffle ciphers that are meant to be used to construct an AEAD with Poly1305.
 */
@Alpha
public abstract class SnuffleCipher implements IndCpaCipher {

  public static final int BLOCK_SIZE_IN_INTS = 16;
  public static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
  static final int KEY_SIZE_IN_INTS = 8;
  public static final int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;

  static final byte[] ZERO_16_BYTES = new byte[16];

  static final int[] SIGMA =
      toIntArray(
          ByteBuffer.wrap(
              new byte[] {
                'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
              }));

  final ImmutableByteArray key;

  SnuffleCipher(final byte[] key) {
    if (key.length != KEY_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("The key length in bytes must be 32.");
    }
    this.key = ImmutableByteArray.of(key);
  }

  /**
   * Constructs a new ChaCha20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     SnuffleCipher#KEY_SIZE_IN_BYTES}.
   */
  static SnuffleCipher chaCha20(final byte[] key) {
    return new ChaCha20(key);
  }

  /**
   * Constructs a new XChaCha20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     SnuffleCipher#KEY_SIZE_IN_BYTES}.
   */
  static SnuffleCipher xChaCha20(final byte[] key) {
    return new XChaCha20(key);
  }

  /**
   * Constructs a new XSalsa20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     SnuffleCipher#KEY_SIZE_IN_BYTES}.
   */
  static SnuffleCipher xSalsa20(final byte[] key) {
    return new XSalsa20(key);
  }

  static int rotateLeft(int x, int y) {
    return (x << y) | (x >>> -y);
  }

  static int[] toIntArray(ByteBuffer in) {
    IntBuffer intBuffer = in.order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
    int[] ret = new int[intBuffer.remaining()];
    intBuffer.get(ret);
    return ret;
  }

  int[] shuffleAdd(int[] state) {
    int[] x = Arrays.copyOf(state, state.length);
    shuffle(x);
    for (int i = 0; i < state.length; i++) {
      x[i] += state[i];
    }
    return x;
  }

  /** Returns a one-time authenticator key as part of an AEAD algorithm (e.g., Poly1305). */
  byte[] getAuthenticatorKey(byte[] nonce) {
    return new KeyStream(this, nonce, 0).first(MAC_KEY_SIZE_IN_BYTES);
  }

  abstract void shuffle(int[] state);

  abstract int[] initialState(final byte[] nonce, int counter);

  abstract void incrementCounter(int[] state);

  abstract int nonceSizeInBytes();

  /**
   * Constructs a {@link KeyStream} to be used in encryption and decryption for sequence generation.
   */
  abstract KeyStream getKeyStream(final byte[] nonce);

  private void process(ByteBuffer output, ByteBuffer input, KeyStream keyStream) {
    // xor the underlying cipher stream with the input.
    ByteBuffer buf = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES).order(ByteOrder.LITTLE_ENDIAN);
    int todo;
    while (input.hasRemaining()) {
      todo = input.remaining() < BLOCK_SIZE_IN_BYTES ? input.remaining() : BLOCK_SIZE_IN_BYTES;
      buf.asIntBuffer().put(keyStream.next());
      for (int j = 0; j < todo; j++) {
        output.put((byte) (input.get() ^ buf.get(j)));
      }
    }
  }

  // TestOnly
  void process(ByteBuffer output, ByteBuffer input, byte[] nonce, int counter) {
    process(output, input, new KeyStream(this, nonce, counter));
  }

  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    ByteBuffer ciphertext = ByteBuffer.allocate(nonceSizeInBytes() + plaintext.length);
    encrypt(ciphertext, plaintext);
    return ciphertext.array();
  }

  void encrypt(ByteBuffer output, final byte[] plaintext) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - nonceSizeInBytes()) {
      throw new GeneralSecurityException("plaintext too long");
    }
    if (output.remaining() < plaintext.length + nonceSizeInBytes()) {
      throw new IllegalArgumentException("Given ByteBuffer output is too small");
    }
    byte[] nonce = Random.randBytes(nonceSizeInBytes());
    output.put(nonce);
    process(output, ByteBuffer.wrap(plaintext), getKeyStream(nonce));
  }

  byte[] decrypt(ByteBuffer ciphertext) throws GeneralSecurityException {
    if (ciphertext.remaining() < nonceSizeInBytes()) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] nonce = new byte[nonceSizeInBytes()];
    ciphertext.get(nonce);
    ByteBuffer plaintext = ByteBuffer.allocate(ciphertext.remaining());
    process(plaintext, ciphertext, getKeyStream(nonce));
    return plaintext.array();
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext) throws GeneralSecurityException {
    return decrypt(ByteBuffer.wrap(ciphertext));
  }
}
