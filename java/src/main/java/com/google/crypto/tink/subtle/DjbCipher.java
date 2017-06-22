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

import static com.google.crypto.tink.subtle.DjbCipherPoly1305.MAC_KEY_SIZE_IN_BYTES;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Abstract base class for class of Djb's ciphers.
 *
 * Class of Djb's ciphers that are meant to be used to construct an AEAD with Poly1305.
 */
public abstract class DjbCipher implements IndCpaCipher {

  static final int BLOCK_SIZE_IN_INTS = 16;
  public static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
  static final int KEY_SIZE_IN_INTS = 8;
  public static final int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;

  static final int[] SIGMA = toIntArray(ByteBuffer.wrap(
      new byte[]{'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k' }));

  // TODO(anergiz): change this to ImmutableByteArray.
  final byte[] key;

  public DjbCipher(final byte[] key) {
    if (key.length != KEY_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("The key length in bytes must be 32.");
    }
    this.key = Arrays.copyOf(key, key.length);
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

  /**
   * Returns a one-time authenticator key as part of an AEAD algorithm (e.g., Poly1305).
   */
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

  /**
   * State generator for DjbCipher types.
   * Stateful and <b>not</b> thread-safe.
   * {@link KeyStream} is not stored as an instance variable in {@link DjbCipher} types to preserve
   * their stateless guarantee. Instead, it is used in local scope to easily maintain the local
   * state inside of a single call (i.e., encrypt or decrypt).
   */
  static class KeyStream {

    private DjbCipher djbCipher;
    private int[] state;
    private int[] keyStreamBlock;
    // The blocks that is returned, can be unaligned from the actual key stream blocks if first is
    // called before next.
    private int[] keyStreamBlockReturn;
    private int currentPosInBlock;
    private boolean readCalled;

    KeyStream(DjbCipher djbCipher, final byte[] nonce, int counter) {
      this.djbCipher = djbCipher;
      keyStreamBlockReturn = new int[BLOCK_SIZE_IN_INTS];
      currentPosInBlock = 0;
      state = djbCipher.initialState(nonce, counter);
      keyStreamBlock = djbCipher.shuffleAdd(state);
      readCalled = false;
    }

    byte[] first(int byteLength) {
      if (readCalled) {
        throw new IllegalStateException("first can only be called once and before next().");
      }
      if (byteLength >= BLOCK_SIZE_IN_BYTES) {
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
          currentPosInBlock, keyStreamBlockReturn, 0, BLOCK_SIZE_IN_INTS - currentPosInBlock);
      djbCipher.incrementCounter(state);
      keyStreamBlock = djbCipher.shuffleAdd(state);
      System.arraycopy(
          keyStreamBlock, 0, keyStreamBlockReturn, BLOCK_SIZE_IN_INTS - currentPosInBlock,
          currentPosInBlock);
      return keyStreamBlockReturn;
    }
  }

  private void process(ByteBuffer output, final byte[] input, int inPos, KeyStream keyStream) {
    // xor the underlying cipher stream with the input.
    ByteBuffer buf = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES).order(ByteOrder.LITTLE_ENDIAN);
    int pos = inPos;
    int inLen = input.length - inPos;
    int todo;
    while (inLen > 0) {
      todo = inLen < BLOCK_SIZE_IN_BYTES ? inLen : BLOCK_SIZE_IN_BYTES;
      buf.asIntBuffer().put(keyStream.next());
      for (int j = 0; j < todo; j++, pos++) {
        output.put((byte) (input[pos] ^ buf.get(j)));
      }
      inLen -= todo;
    }
  }

  // TestOnly
  void process(ByteBuffer output, final byte[] input, int inPos, byte[] nonce, int counter) {
    process(output, input, inPos, new KeyStream(this, nonce, counter));
  }

  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - nonceSizeInBytes()) {
      throw new GeneralSecurityException("plaintext too long");
    }
    byte[] nonce = Random.randBytes(nonceSizeInBytes());
    ByteBuffer ciphertext = ByteBuffer.allocate(plaintext.length + nonceSizeInBytes());
    ciphertext.put(nonce);
    process(ciphertext, plaintext, 0, getKeyStream(nonce));
    return ciphertext.array();
  }

  byte[] decrypt(final byte[] ciphertext, int startPos) throws GeneralSecurityException {
    if (ciphertext.length < nonceSizeInBytes() + startPos) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] nonce = new byte[nonceSizeInBytes()];
    System.arraycopy(ciphertext, startPos, nonce, 0, nonceSizeInBytes());
    ByteBuffer plaintext = ByteBuffer.allocate(ciphertext.length - nonceSizeInBytes() - startPos);
    process(plaintext, ciphertext, startPos + nonceSizeInBytes(), getKeyStream(nonce));
    return plaintext.array();
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext) throws GeneralSecurityException {
    return decrypt(ciphertext, 0);
  }
}
