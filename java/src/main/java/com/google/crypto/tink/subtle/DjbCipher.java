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
 * Abstract base class for class of Djb's ciphers.
 *
 * <p>Class of Djb's ciphers that are meant to be used to construct an AEAD with Poly1305.
 */
@Alpha
public abstract class DjbCipher implements IndCpaCipher {

  static final int BLOCK_SIZE_IN_INTS = 16;
  public static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
  static final int KEY_SIZE_IN_INTS = 8;
  public static final int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;

  private static final byte[] ZERO_16_BYTES = new byte[16];

  static final int[] SIGMA =
      toIntArray(
          ByteBuffer.wrap(
              new byte[] {
                'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
              }));

  final ImmutableByteArray key;

  DjbCipher(final byte[] key) {
    if (key.length != KEY_SIZE_IN_BYTES) {
      throw new IllegalArgumentException("The key length in bytes must be 32.");
    }
    this.key = ImmutableByteArray.of(key);
  }

  /**
   * Constructs a new ChaCha20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  static DjbCipher chaCha20(final byte[] key) {
    return new ChaCha20(key);
  }

  /**
   * Constructs a new XChaCha20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  static DjbCipher xChaCha20(final byte[] key) {
    return new XChaCha20(key);
  }

  /**
   * Constructs a new XSalsa20 cipher with the supplied {@code key}.
   *
   * @throws IllegalArgumentException when {@code key} length is not {@link
   *     DjbCipher#KEY_SIZE_IN_BYTES}.
   */
  static DjbCipher xSalsa20(final byte[] key) {
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

  /**
   * State generator for DjbCipher types. Stateful and <b>not</b> thread-safe. {@link KeyStream} is
   * not stored as an instance variable in {@link DjbCipher} types to preserve their stateless
   * guarantee. Instead, it is used in local scope to easily maintain the local state inside of a
   * single call (i.e., encrypt or decrypt).
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
          currentPosInBlock,
          keyStreamBlockReturn,
          0,
          BLOCK_SIZE_IN_INTS - currentPosInBlock);
      djbCipher.incrementCounter(state);
      keyStreamBlock = djbCipher.shuffleAdd(state);
      System.arraycopy(
          keyStreamBlock,
          0,
          keyStreamBlockReturn,
          BLOCK_SIZE_IN_INTS - currentPosInBlock,
          currentPosInBlock);
      return keyStreamBlockReturn;
    }
  }

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

  abstract static class ChaCha20Base extends DjbCipher {

    private ChaCha20Base(final byte[] key) {
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

    private static void setSigma(int[] state) {
      System.arraycopy(SIGMA, 0, state, 0, SIGMA.length);
    }

    private static void setKey(int[] state, final byte[] key) {
      int[] keyInt = toIntArray(ByteBuffer.wrap(key));
      System.arraycopy(keyInt, 0, state, 4, keyInt.length);
    }

    static byte[] hChaCha20(final byte[] key) {
      return hChaCha20(key, ZERO_16_BYTES);
    }

    static byte[] hChaCha20(final byte[] key, final byte[] nonce) {
      int[] state = new int[BLOCK_SIZE_IN_INTS];
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

  /**
   * Djb's {@link ChaCha20} stream cipher based on RFC7539 (i.e., uses 96-bit random nonces).
   * https://tools.ietf.org/html/rfc7539
   *
   * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
   */
  static class ChaCha20 extends ChaCha20Base {

    private ChaCha20(byte[] key) {
      super(key);
    }

    @Override
    int[] initialState(final byte[] nonce, int counter) {
      // Set the initial state based on https://tools.ietf.org/html/rfc7539#section-2.3
      int[] state = new int[BLOCK_SIZE_IN_INTS];
      ChaCha20Base.setSigma(state);
      ChaCha20Base.setKey(state, key.getBytes());
      state[12] = counter;
      System.arraycopy(toIntArray(ByteBuffer.wrap(nonce)), 0, state, 13, nonceSizeInBytes() / 4);
      return state;
    }

    @Override
    void incrementCounter(int[] state) {
      state[12]++;
    }

    @Override
    int nonceSizeInBytes() {
      return 12;
    }

    @Override
    KeyStream getKeyStream(byte[] nonce) {
      return new KeyStream(this, nonce, 1);
    }
  }

  /**
   * Djb's {@link XChaCha20} stream cipher based on
   * https://download.libsodium.org/doc/advanced/xchacha20.html
   *
   * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
   */
  static class XChaCha20 extends ChaCha20Base {

    /**
     * Constructs a new XChaCha20 cipher with the supplied {@code key}.
     *
     * @throws IllegalArgumentException when {@code key} length is not {@link
     *     DjbCipher#KEY_SIZE_IN_BYTES}.
     */
    private XChaCha20(byte[] key) {
      super(key);
    }

    @Override
    int[] initialState(final byte[] nonce, int counter) {
      // Set the initial state based on https://cr.yp.to/snuffle/xsalsa-20081128.pdf
      int[] state = new int[BLOCK_SIZE_IN_INTS];
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
    void incrementCounter(int[] state) {
      state[12]++;
      if (state[12] == 0) {
        state[13]++;
      }
    }

    @Override
    int nonceSizeInBytes() {
      return 24;
    }

    @Override
    KeyStream getKeyStream(byte[] nonce) {
      return new KeyStream(this, nonce, 1);
    }
  }

  /**
   * Djb's XSalsa20 stream cipher. https://cr.yp.to/snuffle/xsalsa-20081128.pdf
   *
   * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
   */
  static class XSalsa20 extends DjbCipher {

    /**
     * Constructs a new {@link XSalsa20} cipher with the supplied {@code key}.
     *
     * @throws IllegalArgumentException when {@code key} length is not {@link
     *     DjbCipher#KEY_SIZE_IN_BYTES}.
     */
    private XSalsa20(byte[] key) {
      super(key);
    }

    static void quarterRound(int[] x, int a, int b, int c, int d) {
      x[b] ^= rotateLeft(x[a] + x[d], 7);
      x[c] ^= rotateLeft(x[b] + x[a], 9);
      x[d] ^= rotateLeft(x[c] + x[b], 13);
      x[a] ^= rotateLeft(x[d] + x[c], 18);
    }

    static void columnRound(final int[] state) {
      quarterRound(state, 0, 4, 8, 12);
      quarterRound(state, 5, 9, 13, 1);
      quarterRound(state, 10, 14, 2, 6);
      quarterRound(state, 15, 3, 7, 11);
    }

    static void rowRound(final int[] state) {
      quarterRound(state, 0, 1, 2, 3);
      quarterRound(state, 5, 6, 7, 4);
      quarterRound(state, 10, 11, 8, 9);
      quarterRound(state, 15, 12, 13, 14);
    }

    private static void shuffleInternal(final int[] state) {
      for (int i = 0; i < 10; i++) {
        columnRound(state);
        rowRound(state);
      }
    }

    @Override
    void shuffle(final int[] state) {
      shuffleInternal(state);
    }

    private static void setSigma(int[] state) {
      state[0] = SIGMA[0];
      state[5] = SIGMA[1];
      state[10] = SIGMA[2];
      state[15] = SIGMA[3];
    }

    private static void setKey(int[] state, final byte[] key) {
      int[] keyInt = toIntArray(ByteBuffer.wrap(key));
      System.arraycopy(keyInt, 0, state, 1, 4);
      System.arraycopy(keyInt, 4, state, 11, 4);
    }

    static byte[] hSalsa20(final byte[] key) {
      return hSalsa20(key, ZERO_16_BYTES);
    }

    private static byte[] hSalsa20(final byte[] key, final byte[] nonce) {
      int[] state = new int[BLOCK_SIZE_IN_INTS];
      setSigma(state);
      setKey(state, key);
      int[] nonceInt = toIntArray(ByteBuffer.wrap(nonce));
      state[6] = nonceInt[0];
      state[7] = nonceInt[1];
      state[8] = nonceInt[2];
      state[9] = nonceInt[3];
      shuffleInternal(state);
      // state[0] = state[0]
      state[1] = state[5];
      state[2] = state[10];
      state[3] = state[15];
      state[4] = state[6];
      state[5] = state[7];
      state[6] = state[8];
      state[7] = state[9];
      ByteBuffer buf = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
      buf.asIntBuffer().put(state, 0, 8);
      return buf.array();
    }

    @Override
    int[] initialState(final byte[] nonce, int counter) {
      // Set the initial state based on https://cr.yp.to/snuffle/xsalsa-20081128.pdf
      int[] state = new int[BLOCK_SIZE_IN_INTS];
      setSigma(state);
      setKey(state, hSalsa20(key.getBytes(), nonce));
      int[] nonceInt = toIntArray(ByteBuffer.wrap(nonce));
      state[6] = nonceInt[4];
      state[7] = nonceInt[5];
      state[8] = counter;
      state[9] = 0;
      return state;
    }

    @Override
    void incrementCounter(int[] state) {
      state[8]++;
      if (state[8] == 0) {
        state[9]++;
      }
    }

    @Override
    int nonceSizeInBytes() {
      return 24;
    }

    @Override
    KeyStream getKeyStream(byte[] nonce) {
      KeyStream keyStream = new KeyStream(this, nonce, 0);
      keyStream.first(MAC_KEY_SIZE_IN_BYTES); // skip the aead sub key.
      return keyStream;
    }
  }
}
