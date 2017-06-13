package com.google.crypto.tink.subtle;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Abstract base class for class of DJB's ciphers.
 */
public abstract class DJBCipher implements IndCpaCipher {

  static final int BLOCK_SIZE_IN_INTS = 16;
  public static final int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
  static final int KEY_SIZE_IN_INTS = 8;
  public static final int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;

  static final int[] SIGMA = toIntArray(ByteBuffer.wrap(
      new byte[]{'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k' }));

  // TODO(anergiz): change this to ImmutableByteArray.
  protected final byte[] key;

  public DJBCipher(final byte[] key) {
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

  void shuffleAdd(ByteBuffer output, final int[] state) {
    int[] x = Arrays.copyOf(state, state.length);
    shuffle(x);
    for (int i = 0; i < state.length; i++) {
      x[i] += state[i];
    }
    output.asIntBuffer().put(x);

  }

  abstract int[] initialState(byte[] nonce, int counter);

  abstract void incrementCounter(int[] state);

  abstract int nonceSizeInBytes();

  void process(ByteBuffer output, final byte[] input, int inPos, byte[] nonce, int counter) {
    int[] state = initialState(nonce, counter);

    // xor the underlying cipher stream with the input.
    ByteBuffer buf = ByteBuffer.allocate(BLOCK_SIZE_IN_BYTES).order(ByteOrder.LITTLE_ENDIAN);
    int pos = inPos;
    int inLen = input.length - inPos;
    int todo;
    while (inLen > 0) {
      todo = inLen < BLOCK_SIZE_IN_BYTES ? inLen : BLOCK_SIZE_IN_BYTES;
      shuffleAdd(buf, state);
      for (int j = 0; j < todo; j++, pos++) {
        output.put((byte) (input[pos] ^ buf.array()[j]));
      }
      inLen -= todo;
      incrementCounter(state);
    }
  }

  @Override
  public byte[] encrypt(final byte[] plaintext) throws GeneralSecurityException {
    if (plaintext.length > Integer.MAX_VALUE - nonceSizeInBytes()) {
      throw new GeneralSecurityException("plaintext too long");
    }
    byte[] nonce = Random.randBytes(nonceSizeInBytes());
    ByteBuffer ciphertext = ByteBuffer.allocate(plaintext.length + nonceSizeInBytes());
    ciphertext.put(nonce);
    process(ciphertext, plaintext, 0, nonce, 1);
    return ciphertext.array();
  }

  byte[] decrypt(final byte[] ciphertext, int startPos) throws GeneralSecurityException {
    if (ciphertext.length < nonceSizeInBytes() + startPos) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] nonce = new byte[nonceSizeInBytes()];
    System.arraycopy(ciphertext, startPos, nonce, 0, nonceSizeInBytes());
    ByteBuffer plaintext = ByteBuffer.allocate(ciphertext.length - nonceSizeInBytes() - startPos);
    process(plaintext, ciphertext, startPos + nonceSizeInBytes(), nonce, 1);
    return plaintext.array();
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext) throws GeneralSecurityException {
    return decrypt(ciphertext, 0);
  }
}