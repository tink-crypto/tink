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
import java.nio.IntBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Abstract base class for class of Djb's ciphers.
 */
public abstract class DjbCipher implements IndCpaCipher {

  static final int BLOCK_SIZE_IN_INTS = 16;
  public static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
  static final int KEY_SIZE_IN_INTS = 8;
  public static final int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;

  static final int[] SIGMA = toIntArray(ByteBuffer.wrap(
      new byte[]{'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k' }));

  // TODO(anergiz): change this to ImmutableByteArray.
  protected final byte[] key;

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

  abstract void shuffle(final int[] state);

  int[] shuffleAdd(final int[] state) {
    int[] x = Arrays.copyOf(state, state.length);
    shuffle(x);
    for (int i = 0; i < state.length; i++) {
      x[i] += state[i];
    }
    return x;
  }

  abstract int[] initialState(byte[] nonce, int counter);

  abstract void incrementCounter(int[] state);

  abstract int nonceSizeInBytes();

  /**
   * State generator for DjbCipher types.
   * Stateful and <b>not</b> thread-safe.
   * {@link StateGen} is not stored as an instance variable in {@link DjbCipher} types to preserve
   * their stateless guarantee. Instead, it is used in local scope to easily maintain the local
   * state inside of a single call (i.e., encrypt or decrypt).
   */
  static class StateGen {

    private DjbCipher djbCipher;
    private int[] state;
    private int[] shuffledState;
    private int[] cachedShuffledState;
    private int currentPos;
    private boolean readCalled;

    StateGen(DjbCipher djbCipher, final byte[] nonce, int counter) {
      this.djbCipher = djbCipher;
      cachedShuffledState = new int[BLOCK_SIZE_IN_INTS];
      currentPos = 0;
      state = djbCipher.initialState(nonce, counter);
      shuffledState = djbCipher.shuffleAdd(state);
      readCalled = false;
    }

    byte[] read(int length) {
      if (readCalled) {
        throw new IllegalStateException("read can only be called once and before next().");
      }
      if (length >= BLOCK_SIZE_IN_BYTES) {
        throw new IllegalArgumentException(
            String.format("length must be less than 64. length: %d", length));
      }
      if (length % 4 != 0) {
        throw new IllegalArgumentException(
            String.format("length must be a multiple of 8. length: %d", length));
      }
      readCalled = true;
      currentPos = length / 4;
      ByteBuffer out = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
      out.asIntBuffer().put(shuffledState, 0, length / 4);
      return out.array();
    }

    int[] next() {
      readCalled = true;
      System.arraycopy(
          shuffledState, currentPos, cachedShuffledState, 0, BLOCK_SIZE_IN_INTS - currentPos);
      djbCipher.incrementCounter(state);
      shuffledState = djbCipher.shuffleAdd(state);
      System.arraycopy(
          shuffledState, 0, cachedShuffledState, BLOCK_SIZE_IN_INTS - currentPos, currentPos);
      return cachedShuffledState;
    }
  }

  void process(ByteBuffer output, final byte[] input, int inPos, StateGen stateGen) {
    // xor the underlying cipher stream with the input.
    ByteBuffer buf = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES).order(ByteOrder.LITTLE_ENDIAN);
    int pos = inPos;
    int inLen = input.length - inPos;
    int todo;
    while (inLen > 0) {
      todo = inLen < BLOCK_SIZE_IN_BYTES ? inLen : BLOCK_SIZE_IN_BYTES;
      buf.asIntBuffer().put(stateGen.next());
      for (int j = 0; j < todo; j++, pos++) {
        output.put((byte) (input[pos] ^ buf.get(j)));
      }
      inLen -= todo;
    }
  }

  // TestOnly
  void process(ByteBuffer output, final byte[] input, int inPos, byte[] nonce, int counter) {
    process(output, input, inPos, new StateGen(this, nonce, counter));
  }

  /**
   * Returns the AEAD sub key.
   */
  abstract byte[] getAeadSubKey(final byte[] nonce);

  /**
   * Constructs a {@link StateGen} to be used in encryption and decryption for sequence generation.
   */
  abstract StateGen constructForEncDec(final byte[] nonce);

  public byte[] encrypt(final byte[] plaintext, byte[] aeadSubKey) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - nonceSizeInBytes()) {
      throw new GeneralSecurityException("plaintext too long");
    }
    byte[] nonce = Random.randBytes(nonceSizeInBytes());
    if (aeadSubKey != null) {
      System.arraycopy(getAeadSubKey(nonce), 0, aeadSubKey, 0, aeadSubKey.length);
    }
    ByteBuffer ciphertext = ByteBuffer.allocate(plaintext.length + nonceSizeInBytes());
    ciphertext.put(nonce);
    process(ciphertext, plaintext, 0, constructForEncDec(nonce));
    return ciphertext.array();
  }

  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    return encrypt(plaintext, null);
  }

  byte[] decrypt(final byte[] ciphertext, int startPos) throws GeneralSecurityException {
    if (ciphertext.length < nonceSizeInBytes() + startPos) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] nonce = new byte[nonceSizeInBytes()];
    System.arraycopy(ciphertext, startPos, nonce, 0, nonceSizeInBytes());
    ByteBuffer plaintext = ByteBuffer.allocate(ciphertext.length - nonceSizeInBytes() - startPos);
    process(plaintext, ciphertext, startPos + nonceSizeInBytes(), constructForEncDec(nonce));
    return plaintext.array();
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext) throws GeneralSecurityException {
    return decrypt(ciphertext, 0);
  }
}
