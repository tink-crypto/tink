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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.common.truth.Truth;
import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.subtle.DjbCipher.ChaCha20;
import com.google.crypto.tink.subtle.DjbCipher.KeyStream;
import com.google.crypto.tink.subtle.DjbCipher.XChaCha20;
import com.google.crypto.tink.subtle.DjbCipher.XSalsa20;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Unit tests for {@link DjbCipher}.
 */
@RunWith(Suite.class)
@SuiteClasses({
    DjbCipherTest.BaseTest.class,
    DjbCipherTest.ChaCha20Test.class,
    DjbCipherTest.XChaCha20Test.class,
    DjbCipherTest.XSalsa20Test.class
})
public class DjbCipherTest {

  static class MockDjbCipher extends DjbCipher {

    public MockDjbCipher(byte[] key) {
      super(key);
    }

    @Override
    void shuffle(int[] state) {
      for (int i = 0; i < state.length; i++) {
        state[i] *= state[15];  // at least diffuse the counter
      }
    }

    @Override
    int[] initialState(byte[] nonce, int counter) {
      IntBuffer b = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
      return new int[]{
          b.get(), b.get(), b.get(), b.get(), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, counter};
    }

    @Override
    void incrementCounter(int[] state) {
      state[15]++;
    }

    @Override
    int nonceSizeInBytes() {
      return 0;
    }

    @Override
    KeyStream getKeyStream(byte[] nonce) {
      return null;
    }
  }

  static int[] twosCompInt(long[] a) {
    int[] ret = new int[a.length];
    for (int i = 0; i < a.length; i++) {
      ret[i] = (int) (a[i] - (a[i] > Integer.MAX_VALUE ? (1L << 32) : 0));
    }
    return ret;
  }

  static byte[] twosCompByte(int[] a) {
    byte[] ret = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      ret[i] = (byte) (a[i] - (a[i] > Byte.MAX_VALUE ? (1 << 8) : 0));
    }
    return ret;
  }

  /**
   * Unit tests for {@link DjbCipher} abstract class.
   */
  public static class BaseTest {

    @Test
    public void testStateGenNoRead() {
      byte[] nonce = new byte[16];
      nonce[0] = 2;
      nonce[4] = 2;
      nonce[8] = 2;
      nonce[12] = 2;
      KeyStream keyStream = new KeyStream(new MockDjbCipher(new byte[32]), nonce, 3);
      assertThat(keyStream.next()).isEqualTo(
          new int[]{8, 8, 8, 8, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 12});
      assertThat(keyStream.next()).isEqualTo(
          new int[]{10, 10, 10, 10, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 20});
    }

    @Test
    public void testStateGenReadSomeFirst() {
      byte[] nonce = new byte[16];
      nonce[0] = 2;
      nonce[4] = 2;
      nonce[8] = 2;
      nonce[12] = 2;
      KeyStream keyStream = new KeyStream(new MockDjbCipher(new byte[32]), nonce, 3);
      assertThat(keyStream.first(20)).isEqualTo(
          new byte[]{8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 4, 0, 0, 0});
      assertThat(keyStream.next()).isEqualTo(
          new int[]{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 12, 10, 10, 10, 10, 5});
      assertThat(keyStream.next()).isEqualTo(
          new int[]{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 20, 12, 12, 12, 12, 6});
    }

    @Test
    public void testStateGenReadLengthGT16ThrowsIllegalArgException() {
      KeyStream keyStream = new KeyStream(new MockDjbCipher(new byte[32]), new byte[16], 3);
      try {
        keyStream.first(64);
        fail("Expected IllegalArgumentException.");
      } catch (IllegalArgumentException e) {
        assertThat(e).hasMessageThat().containsMatch("length must be less than 64. length: 64");
      }
    }

    @Test
    public void testStateGenReadCalledTwiceThrowsIllegalStateException() {
      KeyStream keyStream = new KeyStream(new MockDjbCipher(new byte[32]), new byte[16], 3);
      keyStream.first(60);
      try {
        keyStream.first(4);
        fail("Expected IllegalStateException.");
      } catch (IllegalStateException e) {
        assertThat(e).hasMessageThat().containsMatch(
            "first can only be called once and before next().");
      }
    }

    @Test
    public void testStateGenReadCalledAfterNextThrowsIllegalStateException() {
      KeyStream keyStream = new KeyStream(new MockDjbCipher(new byte[32]), new byte[16], 3);
      keyStream.next();
      try {
        keyStream.first(1);
        fail("Expected IllegalStateException.");
      } catch (IllegalStateException e) {
        assertThat(e).hasMessageThat().containsMatch(
            "first can only be called once and before next().");
      }
    }
  }

  private abstract static class DjbCipherTestBase {

    protected abstract DjbCipher createInstance(byte[] key);

    @Test
    public void testRandomInputs() throws GeneralSecurityException {
      for (int i = 0; i < 1000; i++) {
        byte[] expectedInput = Random.randBytes(new java.util.Random().nextInt(300));
        byte[] key = Random.randBytes(32);
        DjbCipher cipher = createInstance(key);
        byte[] output = cipher.encrypt(expectedInput);
        byte[] nonce = Arrays.copyOf(output, cipher.nonceSizeInBytes());
        byte[] actualInput = cipher.decrypt(output);
        assertTrue(
            String.format(
                "\n\nMessage: %s\nKey: %s\nNonce: %s\nOutput: %s\nDecrypted Msg: %s\n",
                TestUtil.hexEncode(expectedInput),
                TestUtil.hexEncode(key),
                TestUtil.hexEncode(nonce),
                TestUtil.hexEncode(output),
                TestUtil.hexEncode(actualInput)),
            Arrays.equals(expectedInput, actualInput));
      }
    }

    @Test
    public void testNewCipherThrowsIllegalArgExpWhenKeyLenIsLessThan32() {
      try {
        createInstance(new byte[1]);
        fail("Expected IllegalArgumentException.");
      } catch (IllegalArgumentException e) {
        assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
      }
    }

    @Test
    public void testNewCipherThrowsIllegalArgExpWhenKeyLenIsGreaterThan32() {
      try {
        createInstance(new byte[33]);
        fail("Expected IllegalArgumentException.");
      } catch (IllegalArgumentException e) {
        assertThat(e).hasMessageThat().containsMatch("The key length in bytes must be 32.");
      }
    }

    @Test
    public void testDecryptThrowsGeneralSecurityExpWhenCiphertextIsTooShort() {
      DjbCipher cipher = createInstance(new byte[32]);
      try {
        cipher.decrypt(new byte[2]);
        fail("Expected GeneralSecurityException.");
      } catch (GeneralSecurityException e) {
        assertThat(e).hasMessageThat().containsMatch("ciphertext too short");
      }
    }
  }

  /**
   * Unit tests for {@link DjbCipher#chaCha20(byte[])}
   */
  public static class ChaCha20Test extends DjbCipherTestBase {

    private static DjbCipher dummyCipher = DjbCipher.chaCha20(new byte[32]);

    @Override
    protected DjbCipher createInstance(byte[] key) {
      return DjbCipher.chaCha20(key);
    }

    /**
     * https://tools.ietf.org/html/rfc7539#section-2.1.1
     */
    @Test
    public void testQuarterRound() {
      int[] x = twosCompInt(new long[]{0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567});
      ChaCha20.quarterRound(x, 0, 1, 2, 3);
      Truth.assertThat(x).isEqualTo(
          twosCompInt(new long[]{0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb}));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#section-2.2.1
     */
    @Test
    public void testQuarterRound16() {
      int[] x = twosCompInt(new long[]{
          0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
          0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
          0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
          0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320});
      ChaCha20.quarterRound(x, 2, 7, 8, 13);
      Truth.assertThat(x).isEqualTo(
          twosCompInt(new long[]{
              0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
              0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
              0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
              0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320}));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#section-2.3.2
     */
    @Test
    public void testChaCha20Core() {
      int[] in = {
          0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
          0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
          0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
          0x00000001, 0x09000000, 0x4a000000, 0x00000000};
      ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
      buf.asIntBuffer().put(dummyCipher.shuffleAdd(in));
      Truth.assertThat(buf.array()).isEqualTo(twosCompByte(new int[]{
          0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
          0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
          0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
          0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
          0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
          0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
          0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
          0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
      }));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#section-2.4.2
     */
    @Test
    public void testChaCha20() {
      byte[] in = (
          "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
              + "the future, sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);
      byte[] key = {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
          0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
      byte[] nonce = {
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
      DjbCipher cipher = createInstance(key);
      ByteBuffer out = ByteBuffer.allocate(in.length);
      cipher.process(out, ByteBuffer.wrap(in), nonce, 1);
      Truth.assertThat(out.array()).isEqualTo(twosCompByte(new int[]{
          0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
          0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
          0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
          0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
          0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
          0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
          0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
          0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
          0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
          0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
          0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
          0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
          0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
          0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
          0x87, 0x4d}));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#appendix-A.1
     * Test Vector #1
     */
    @Test
    public void testChaCha20Core1() {
      int[] in = {
          0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000};
      ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
      buf.asIntBuffer().put(dummyCipher.shuffleAdd(in));
      Truth.assertThat(buf.array()).isEqualTo(twosCompByte(new int[]{
          0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
          0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
          0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
          0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
          0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
          0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
          0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
          0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
      }));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#appendix-A.1
     * Test Vector #2
     */
    @Test
    public void testChaCha20Core2() {
      int[] in = {
          0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000001, 0x00000000, 0x00000000, 0x00000000};
      ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
      buf.asIntBuffer().put(dummyCipher.shuffleAdd(in));
      Truth.assertThat(buf.array()).isEqualTo(twosCompByte(new int[]{
          0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
          0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
          0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
          0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
          0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
          0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
          0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
          0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f
      }));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#appendix-A.1
     * Test Vector #3
     */
    @Test
    public void testChaCha20Core3() {
      int[] in = {
          0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x01000000,
          0x00000001, 0x00000000, 0x00000000, 0x00000000};
      ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
      buf.asIntBuffer().put(dummyCipher.shuffleAdd(in));
      Truth.assertThat(buf.array()).isEqualTo(twosCompByte(new int[]{
          0x3a, 0xeb, 0x52, 0x24, 0xec, 0xf8, 0x49, 0x92,
          0x9b, 0x9d, 0x82, 0x8d, 0xb1, 0xce, 0xd4, 0xdd,
          0x83, 0x20, 0x25, 0xe8, 0x01, 0x8b, 0x81, 0x60,
          0xb8, 0x22, 0x84, 0xf3, 0xc9, 0x49, 0xaa, 0x5a,
          0x8e, 0xca, 0x00, 0xbb, 0xb4, 0xa7, 0x3b, 0xda,
          0xd1, 0x92, 0xb5, 0xc4, 0x2f, 0x73, 0xf2, 0xfd,
          0x4e, 0x27, 0x36, 0x44, 0xc8, 0xb3, 0x61, 0x25,
          0xa6, 0x4a, 0xdd, 0xeb, 0x00, 0x6c, 0x13, 0xa0
      }));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#appendix-A.1
     * Test Vector #4
     */
    @Test
    public void testChaCha20Core4() {
      int[] in = {
          0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
          0x0000ff00, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000002, 0x00000000, 0x00000000, 0x00000000};
      ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
      buf.asIntBuffer().put(dummyCipher.shuffleAdd(in));
      Truth.assertThat(buf.array()).isEqualTo(twosCompByte(new int[]{
          0x72, 0xd5, 0x4d, 0xfb, 0xf1, 0x2e, 0xc4, 0x4b,
          0x36, 0x26, 0x92, 0xdf, 0x94, 0x13, 0x7f, 0x32,
          0x8f, 0xea, 0x8d, 0xa7, 0x39, 0x90, 0x26, 0x5e,
          0xc1, 0xbb, 0xbe, 0xa1, 0xae, 0x9a, 0xf0, 0xca,
          0x13, 0xb2, 0x5a, 0xa2, 0x6c, 0xb4, 0xa6, 0x48,
          0xcb, 0x9b, 0x9d, 0x1b, 0xe6, 0x5b, 0x2c, 0x09,
          0x24, 0xa6, 0x6c, 0x54, 0xd5, 0x45, 0xec, 0x1b,
          0x73, 0x74, 0xf4, 0x87, 0x2e, 0x99, 0xf0, 0x96
      }));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#appendix-A.1
     * Test Vector #5
     */
    @Test
    public void testChaCha20Core5() {
      int[] in = {
          0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x00000000,
          0x00000000, 0x00000000, 0x00000000, 0x02000000};
      ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
      buf.asIntBuffer().put(dummyCipher.shuffleAdd(in));
      Truth.assertThat(buf.array()).isEqualTo(twosCompByte(new int[]{
          0xc2, 0xc6, 0x4d, 0x37, 0x8c, 0xd5, 0x36, 0x37,
          0x4a, 0xe2, 0x04, 0xb9, 0xef, 0x93, 0x3f, 0xcd,
          0x1a, 0x8b, 0x22, 0x88, 0xb3, 0xdf, 0xa4, 0x96,
          0x72, 0xab, 0x76, 0x5b, 0x54, 0xee, 0x27, 0xc7,
          0x8a, 0x97, 0x0e, 0x0e, 0x95, 0x5c, 0x14, 0xf3,
          0xa8, 0x8e, 0x74, 0x1b, 0x97, 0xc2, 0x86, 0xf7,
          0x5f, 0x8f, 0xc2, 0x99, 0xe8, 0x14, 0x83, 0x62,
          0xfa, 0x19, 0x8a, 0x39, 0x53, 0x1b, 0xed, 0x6d
      }));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#appendix-A.2
     * Test Vector #1
     */
    @Test
    public void testChaCha201() {
      byte[] in = new byte[64];
      byte[] key = new byte[32];
      byte[] nonce = new byte[12];
      DjbCipher cipher = createInstance(key);
      ByteBuffer out = ByteBuffer.allocate(in.length);
      cipher.process(out, ByteBuffer.wrap(in), nonce, 0);
      Truth.assertThat(out.array()).isEqualTo(twosCompByte(new int[]{
          0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
          0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
          0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
          0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
          0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
          0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
          0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
          0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86}));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#appendix-A.2
     * Test Vector #2
     */
    @Test
    public void testChaCha202() {
      byte[] in = (
          "Any submission to the IETF intended by the Contributor for publication as all or "
              + "part of an IETF Internet-Draft or RFC and any statement made within the context "
              + "of an IETF activity is considered an \"IETF Contribution\". Such statements "
              + "include oral statements in IETF sessions, as well as written and electronic "
              + "communications made at any time or place, which are addressed to")
          .getBytes(StandardCharsets.US_ASCII);
      byte[] key = new byte[32];
      key[31] = 1;
      byte[] nonce = new byte[12];
      nonce[11] = 2;
      DjbCipher cipher = createInstance(key);
      ByteBuffer out = ByteBuffer.allocate(in.length);
      cipher.process(out, ByteBuffer.wrap(in), nonce, 1);
      Truth.assertThat(out.array()).isEqualTo(twosCompByte(new int[]{
          0xa3, 0xfb, 0xf0, 0x7d, 0xf3, 0xfa, 0x2f, 0xde,
          0x4f, 0x37, 0x6c, 0xa2, 0x3e, 0x82, 0x73, 0x70,
          0x41, 0x60, 0x5d, 0x9f, 0x4f, 0x4f, 0x57, 0xbd,
          0x8c, 0xff, 0x2c, 0x1d, 0x4b, 0x79, 0x55, 0xec,
          0x2a, 0x97, 0x94, 0x8b, 0xd3, 0x72, 0x29, 0x15,
          0xc8, 0xf3, 0xd3, 0x37, 0xf7, 0xd3, 0x70, 0x05,
          0x0e, 0x9e, 0x96, 0xd6, 0x47, 0xb7, 0xc3, 0x9f,
          0x56, 0xe0, 0x31, 0xca, 0x5e, 0xb6, 0x25, 0x0d,
          0x40, 0x42, 0xe0, 0x27, 0x85, 0xec, 0xec, 0xfa,
          0x4b, 0x4b, 0xb5, 0xe8, 0xea, 0xd0, 0x44, 0x0e,
          0x20, 0xb6, 0xe8, 0xdb, 0x09, 0xd8, 0x81, 0xa7,
          0xc6, 0x13, 0x2f, 0x42, 0x0e, 0x52, 0x79, 0x50,
          0x42, 0xbd, 0xfa, 0x77, 0x73, 0xd8, 0xa9, 0x05,
          0x14, 0x47, 0xb3, 0x29, 0x1c, 0xe1, 0x41, 0x1c,
          0x68, 0x04, 0x65, 0x55, 0x2a, 0xa6, 0xc4, 0x05,
          0xb7, 0x76, 0x4d, 0x5e, 0x87, 0xbe, 0xa8, 0x5a,
          0xd0, 0x0f, 0x84, 0x49, 0xed, 0x8f, 0x72, 0xd0,
          0xd6, 0x62, 0xab, 0x05, 0x26, 0x91, 0xca, 0x66,
          0x42, 0x4b, 0xc8, 0x6d, 0x2d, 0xf8, 0x0e, 0xa4,
          0x1f, 0x43, 0xab, 0xf9, 0x37, 0xd3, 0x25, 0x9d,
          0xc4, 0xb2, 0xd0, 0xdf, 0xb4, 0x8a, 0x6c, 0x91,
          0x39, 0xdd, 0xd7, 0xf7, 0x69, 0x66, 0xe9, 0x28,
          0xe6, 0x35, 0x55, 0x3b, 0xa7, 0x6c, 0x5c, 0x87,
          0x9d, 0x7b, 0x35, 0xd4, 0x9e, 0xb2, 0xe6, 0x2b,
          0x08, 0x71, 0xcd, 0xac, 0x63, 0x89, 0x39, 0xe2,
          0x5e, 0x8a, 0x1e, 0x0e, 0xf9, 0xd5, 0x28, 0x0f,
          0xa8, 0xca, 0x32, 0x8b, 0x35, 0x1c, 0x3c, 0x76,
          0x59, 0x89, 0xcb, 0xcf, 0x3d, 0xaa, 0x8b, 0x6c,
          0xcc, 0x3a, 0xaf, 0x9f, 0x39, 0x79, 0xc9, 0x2b,
          0x37, 0x20, 0xfc, 0x88, 0xdc, 0x95, 0xed, 0x84,
          0xa1, 0xbe, 0x05, 0x9c, 0x64, 0x99, 0xb9, 0xfd,
          0xa2, 0x36, 0xe7, 0xe8, 0x18, 0xb0, 0x4b, 0x0b,
          0xc3, 0x9c, 0x1e, 0x87, 0x6b, 0x19, 0x3b, 0xfe,
          0x55, 0x69, 0x75, 0x3f, 0x88, 0x12, 0x8c, 0xc0,
          0x8a, 0xaa, 0x9b, 0x63, 0xd1, 0xa1, 0x6f, 0x80,
          0xef, 0x25, 0x54, 0xd7, 0x18, 0x9c, 0x41, 0x1f,
          0x58, 0x69, 0xca, 0x52, 0xc5, 0xb8, 0x3f, 0xa3,
          0x6f, 0xf2, 0x16, 0xb9, 0xc1, 0xd3, 0x00, 0x62,
          0xbe, 0xbc, 0xfd, 0x2d, 0xc5, 0xbc, 0xe0, 0x91,
          0x19, 0x34, 0xfd, 0xa7, 0x9a, 0x86, 0xf6, 0xe6,
          0x98, 0xce, 0xd7, 0x59, 0xc3, 0xff, 0x9b, 0x64,
          0x77, 0x33, 0x8f, 0x3d, 0xa4, 0xf9, 0xcd, 0x85,
          0x14, 0xea, 0x99, 0x82, 0xcc, 0xaf, 0xb3, 0x41,
          0xb2, 0x38, 0x4d, 0xd9, 0x02, 0xf3, 0xd1, 0xab,
          0x7a, 0xc6, 0x1d, 0xd2, 0x9c, 0x6f, 0x21, 0xba,
          0x5b, 0x86, 0x2f, 0x37, 0x30, 0xe3, 0x7c, 0xfd,
          0xc4, 0xfd, 0x80, 0x6c, 0x22, 0xf2, 0x21}));
    }

    /**
     * https://tools.ietf.org/html/rfc7539#appendix-A.2
     * Test Vector #3
     */
    @Test
    public void testChaCha203() {
      byte[] in = twosCompByte(new int[]{
          0x27, 0x54, 0x77, 0x61, 0x73, 0x20, 0x62, 0x72,
          0x69, 0x6c, 0x6c, 0x69, 0x67, 0x2c, 0x20, 0x61,
          0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
          0x6c, 0x69, 0x74, 0x68, 0x79, 0x20, 0x74, 0x6f,
          0x76, 0x65, 0x73, 0x0a, 0x44, 0x69, 0x64, 0x20,
          0x67, 0x79, 0x72, 0x65, 0x20, 0x61, 0x6e, 0x64,
          0x20, 0x67, 0x69, 0x6d, 0x62, 0x6c, 0x65, 0x20,
          0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77,
          0x61, 0x62, 0x65, 0x3a, 0x0a, 0x41, 0x6c, 0x6c,
          0x20, 0x6d, 0x69, 0x6d, 0x73, 0x79, 0x20, 0x77,
          0x65, 0x72, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
          0x62, 0x6f, 0x72, 0x6f, 0x67, 0x6f, 0x76, 0x65,
          0x73, 0x2c, 0x0a, 0x41, 0x6e, 0x64, 0x20, 0x74,
          0x68, 0x65, 0x20, 0x6d, 0x6f, 0x6d, 0x65, 0x20,
          0x72, 0x61, 0x74, 0x68, 0x73, 0x20, 0x6f, 0x75,
          0x74, 0x67, 0x72, 0x61, 0x62, 0x65, 0x2e
      });
      byte[] key = twosCompByte(new int[]{
          0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
          0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
          0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
          0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0});
      byte[] nonce = new byte[12];
      nonce[11] = 2;
      DjbCipher cipher = createInstance(key);
      ByteBuffer out = ByteBuffer.allocate(in.length);
      cipher.process(out, ByteBuffer.wrap(in), nonce, 42);
      Truth.assertThat(out.array()).isEqualTo(twosCompByte(new int[]{
          0x62, 0xe6, 0x34, 0x7f, 0x95, 0xed, 0x87, 0xa4,
          0x5f, 0xfa, 0xe7, 0x42, 0x6f, 0x27, 0xa1, 0xdf,
          0x5f, 0xb6, 0x91, 0x10, 0x04, 0x4c, 0x0d, 0x73,
          0x11, 0x8e, 0xff, 0xa9, 0x5b, 0x01, 0xe5, 0xcf,
          0x16, 0x6d, 0x3d, 0xf2, 0xd7, 0x21, 0xca, 0xf9,
          0xb2, 0x1e, 0x5f, 0xb1, 0x4c, 0x61, 0x68, 0x71,
          0xfd, 0x84, 0xc5, 0x4f, 0x9d, 0x65, 0xb2, 0x83,
          0x19, 0x6c, 0x7f, 0xe4, 0xf6, 0x05, 0x53, 0xeb,
          0xf3, 0x9c, 0x64, 0x02, 0xc4, 0x22, 0x34, 0xe3,
          0x2a, 0x35, 0x6b, 0x3e, 0x76, 0x43, 0x12, 0xa6,
          0x1a, 0x55, 0x32, 0x05, 0x57, 0x16, 0xea, 0xd6,
          0x96, 0x25, 0x68, 0xf8, 0x7d, 0x3f, 0x3f, 0x77,
          0x04, 0xc6, 0xa8, 0xd1, 0xbc, 0xd1, 0xbf, 0x4d,
          0x50, 0xd6, 0x15, 0x4b, 0x6d, 0xa7, 0x31, 0xb1,
          0x87, 0xb5, 0x8d, 0xfd, 0x72, 0x8a, 0xfa, 0x36,
          0x75, 0x7a, 0x79, 0x7a, 0xc1, 0x88, 0xd1}));
    }
  }

  /**
   * Unit tests for {@link DjbCipher#xSalsa20(byte[])}
   */
  public static class XSalsa20Test extends DjbCipherTestBase {

    private static final DjbCipher dummyCipher = DjbCipher.xSalsa20(new byte[32]);

    @Override
    protected DjbCipher createInstance(byte[] key) {
      return DjbCipher.xSalsa20(key);
    }

    private static int[] matrix(int[] bytes) {
      return DjbCipher.toIntArray(
          ByteBuffer.wrap(twosCompByte(bytes)).order(ByteOrder.LITTLE_ENDIAN));
    }

    private static void testQuarterRound(long[] in, long[] output) {
      int[] x = twosCompInt(in);
      XSalsa20.quarterRound(x, 0, 1, 2, 3);
      Truth.assertThat(x).isEqualTo(twosCompInt(output));
    }

    private static void testRowRound(long[] in, long[] output) {
      int[] x = twosCompInt(in);
      XSalsa20.rowRound(x);
      Truth.assertThat(x).isEqualTo(twosCompInt(output));
    }

    private static void testColumnRound(long[] in, long[] output) {
      int[] x = twosCompInt(in);
      XSalsa20.columnRound(x);
      Truth.assertThat(x).isEqualTo(twosCompInt(output));
    }

    private static void testDoubleRound(long[] in, long[] output) {
      int[] x = twosCompInt(in);
      XSalsa20.columnRound(x);
      XSalsa20.rowRound(x);
      Truth.assertThat(x).isEqualTo(twosCompInt(output));
    }

    private static void testSalsa20(int[] in, int[] output, int count) {
      int[] x = matrix(in);
      ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
      for (int i = 0; i < count; i++) {
        buf.asIntBuffer().put(dummyCipher.shuffleAdd(x));
        x = DjbCipher.toIntArray(buf);
      }
      Truth.assertThat(buf.array()).isEqualTo(twosCompByte(output));
    }

    /**
     * Section 3
     * http://cr.yp.to/snuffle/spec.pdf
     */
    @Test
    public void testQuarterRounds() {
      testQuarterRound(new long[4], new long[4]);
      testQuarterRound(
          new long[]{0x00000001, 0x00000000, 0x00000000, 0x00000000},
          new long[]{0x08008145, 0x00000080, 0x00010200, 0x20500000});
      testQuarterRound(
          new long[]{0x00000000, 0x00000001, 0x00000000, 0x00000000},
          new long[]{0x88000100, 0x00000001, 0x00000200, 0x00402000});
      testQuarterRound(
          new long[]{0x00000000, 0x00000000, 0x00000001, 0x00000000},
          new long[]{0x80040000, 0x00000000, 0x00000001, 0x00002000});
      testQuarterRound(
          new long[]{0x00000000, 0x00000000, 0x00000000, 0x00000001},
          new long[]{0x00048044, 0x00000080, 0x00010000, 0x20100001});
      testQuarterRound(
          new long[]{0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137},
          new long[]{0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3});
      testQuarterRound(
          new long[]{0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b},
          new long[]{0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c});
    }

    /**
     * Section 4
     * http://cr.yp.to/snuffle/spec.pdf
     */
    @Test
    public void testRowRounds() {
      testRowRound(
          new long[]{
              0x00000001, 0x00000000, 0x00000000, 0x00000000,
              0x00000001, 0x00000000, 0x00000000, 0x00000000,
              0x00000001, 0x00000000, 0x00000000, 0x00000000,
              0x00000001, 0x00000000, 0x00000000, 0x00000000},
          new long[]{
              0x08008145, 0x00000080, 0x00010200, 0x20500000,
              0x20100001, 0x00048044, 0x00000080, 0x00010000,
              0x00000001, 0x00002000, 0x80040000, 0x00000000,
              0x00000001, 0x00000200, 0x00402000, 0x88000100});
      testRowRound(
          new long[]{
              0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
              0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
              0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
              0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a},
          new long[]{
              0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
              0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
              0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
              0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d});
    }

    /**
     * Section 5
     * http://cr.yp.to/snuffle/spec.pdf
     */
    @Test
    public void testColumnRounds() {
      testColumnRound(
          new long[]{
              0x00000001, 0x00000000, 0x00000000, 0x00000000,
              0x00000001, 0x00000000, 0x00000000, 0x00000000,
              0x00000001, 0x00000000, 0x00000000, 0x00000000,
              0x00000001, 0x00000000, 0x00000000, 0x00000000},
          new long[]{
              0x10090288, 0x00000000, 0x00000000, 0x00000000,
              0x00000101, 0x00000000, 0x00000000, 0x00000000,
              0x00020401, 0x00000000, 0x00000000, 0x00000000,
              0x40a04001, 0x00000000, 0x00000000, 0x00000000});
      testColumnRound(
          new long[]{
              0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
              0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
              0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
              0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a},
          new long[]{
              0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
              0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
              0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
              0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8});
    }

    /**
     * Section 6
     * http://cr.yp.to/snuffle/spec.pdf
     */
    @Test
    public void testDoubleRounds() {
      testDoubleRound(
          new long[]{
              0x00000001, 0x00000000, 0x00000000, 0x00000000,
              0x00000000, 0x00000000, 0x00000000, 0x00000000,
              0x00000000, 0x00000000, 0x00000000, 0x00000000,
              0x00000000, 0x00000000, 0x00000000, 0x00000000},
          new long[]{
              0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
              0x08000090, 0x02402200, 0x00004000, 0x00800000,
              0x00010200, 0x20400000, 0x08008104, 0x00000000,
              0x20500000, 0xa0000040, 0x0008180a, 0x612a8020});
      testDoubleRound(
          new long[]{
              0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
              0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
              0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
              0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1},
          new long[]{
              0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
              0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
              0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
              0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277});
    }

    /**
     * Section 8
     * http://cr.yp.to/snuffle/spec.pdf
     */
    @Test
    public void testSalsa20() {
      testSalsa20(
          new int[]{
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
          new int[]{
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
          1);
      testSalsa20(
          new int[]{
              211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37, 191, 187, 234, 136,
              49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48, 86, 16, 179, 207,
              31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113, 238, 55, 204, 36,
              79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243, 88, 118, 104, 54},
          new int[]{
              109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203, 26, 110, 170, 154,
              29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48, 69, 144, 51, 57,
              118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35, 27, 111, 114, 114,
              219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158, 179, 19, 48, 202},
          1);
      testSalsa20(
          new int[]{
              88, 118, 104, 54, 79, 201, 235, 79, 3, 81, 156, 47, 203, 26, 244, 243,
              191, 187, 234, 136, 211, 159, 13, 115, 76, 55, 82, 183, 3, 117, 222, 37,
              86, 16, 179, 207, 49, 237, 179, 48, 1, 106, 178, 219, 175, 199, 166, 48,
              238, 55, 204, 36, 31, 240, 32, 63, 15, 83, 93, 161, 116, 147, 48, 113},
          new int[]{
              179, 19, 48, 202, 219, 236, 232, 135, 111, 155, 110, 18, 24, 232, 95, 158,
              26, 110, 170, 154, 109, 42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203,
              69, 144, 51, 57, 29, 29, 150, 26, 150, 30, 235, 249, 190, 163, 251, 48,
              27, 111, 114, 114, 118, 40, 152, 157, 180, 57, 27, 94, 107, 42, 236, 35},
          1);
      testSalsa20(
          new int[]{
              6, 124, 83, 146, 38, 191, 9, 50, 4, 161, 47, 222, 122, 182, 223, 185,
              75, 27, 0, 216, 16, 122, 7, 89, 162, 104, 101, 147, 213, 21, 54, 95,
              225, 253, 139, 176, 105, 132, 23, 116, 76, 41, 176, 207, 221, 34, 157, 108,
              94, 94, 99, 52, 90, 117, 91, 220, 146, 190, 239, 143, 196, 176, 130, 186},
          new int[]{
              8, 18, 38, 199, 119, 76, 215, 67, 173, 127, 144, 162, 103, 212, 176, 217,
              192, 19, 233, 33, 159, 197, 154, 160, 128, 243, 219, 65, 171, 136, 135, 225,
              123, 11, 68, 86, 237, 82, 20, 155, 133, 189, 9, 83, 167, 116, 194, 78,
              122, 127, 195, 185, 185, 204, 188, 90, 245, 9, 183, 248, 226, 85, 245, 104},
          1000000);
    }

    /**
     * Testing HSalsa20, example 1
     * Section 8
     * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void testHSalsa20_1() {
      DjbCipher cipher = createInstance(twosCompByte(new int[]{
          0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
          0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
          0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
          0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42}));
      int[] state = cipher.initialState(new byte[24], 0);
      int[] hSalsa20 = new int[]{
          state[1], state[2], state[3], state[4], state[11], state[12], state[13], state[14]};
      int[] expected = matrix(new int[]{
          0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
          0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
          0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
          0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89});
      Truth.assertThat(hSalsa20).isEqualTo(expected);
    }

    /**
     * Testing HSalsa20, example 2
     * Section 8
     * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void testHSalsa20_2() {
      DjbCipher cipher = createInstance(twosCompByte(new int[]{
          0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
          0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
          0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
          0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89}));
      byte[] nonce = twosCompByte(new int[]{
          0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
          0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
      int[] state = cipher.initialState(nonce, 0);
      int[] hSalsa20 = new int[]{
          state[1], state[2], state[3], state[4], state[11], state[12], state[13], state[14]};
      int[] expected = matrix(new int[]{
          0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9,
          0x53, 0x62, 0x9b, 0x73, 0x38, 0x20, 0x77, 0x88,
          0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9,
          0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4});
      Truth.assertThat(hSalsa20).isEqualTo(expected);
    }

    /**
     * Testing HSalsa20, example 2
     * Section 8
     * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void testHSalsa20_3() throws NoSuchAlgorithmException {
      DjbCipher cipher = createInstance(twosCompByte(new int[]{
          0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
          0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
          0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
          0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89}));
      byte[] nonce = twosCompByte(new int[]{
          0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
          0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
          0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37});
      int[] state = cipher.initialState(nonce, 0);
      ByteBuffer out = ByteBuffer.allocate(4194304).order(ByteOrder.LITTLE_ENDIAN);
      for (int i = 0; i < 65536; i++) {
        out.asIntBuffer().put(cipher.shuffleAdd(state));
        cipher.incrementCounter(state);
        out.position(out.position() + 64);
      }
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      Truth.assertThat(digest.digest(out.array())).isEqualTo(
          TestUtil.hexDecode("662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2"));
    }

    /**
     * Testing: secretbox vs. stream
     * Section 10
     * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void testHSalsa20_4() throws GeneralSecurityException {
      DjbCipher cipher = createInstance(twosCompByte(new int[]{
          0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
          0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
          0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
          0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89}));
      byte[] ciphertext = twosCompByte(new int[]{
          0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
          0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
          0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
          0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
          0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
          0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
          0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
          0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
          0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
          0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
          0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
          0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
          0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
          0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
          0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
          0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
          0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
          0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
          0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
          0xe3, 0x55, 0xa5});
      byte[] plaintext = cipher.decrypt(ciphertext);
      Truth.assertThat(plaintext).isEqualTo(twosCompByte(new int[]{
          0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5,
          0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
          0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
          0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
          0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
          0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
          0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
          0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
          0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
          0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
          0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
          0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
          0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
          0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
          0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
          0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
          0x5e, 0x07, 0x05}));
    }

    /**
     * Testing: secretbox vs. onetimeauth
     * Section 10
     * http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void testHSalsa20_5() throws GeneralSecurityException {
      DjbCipher cipher = createInstance(twosCompByte(new int[]{
          0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
          0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
          0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
          0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89}));
      byte[] aeadKey = cipher.getAuthenticatorKey(twosCompByte(new int[]{
          0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
          0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
          0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37}));
      Truth.assertThat(aeadKey).isEqualTo(twosCompByte(new int[]{
          0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91,
          0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d, 0x3c, 0x25,
          0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65,
          0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80}));
    }
  }

  /**
   * Unit tests for {@link DjbCipher#xChaCha20(byte[])}
   */
  public static class XChaCha20Test extends DjbCipherTestBase {

    // From libsodium's test/default/xchacha20.c (tv_hchacha20)
    private static String[][] hChaCha20Tvs = {
        {"24f11cce8a1b3d61e441561a696c1c1b7e173d084fd4812425435a8896a013dc",
            "d9660c5900ae19ddad28d6e06e45fe5e",
            "5966b3eec3bff1189f831f06afe4d4e3be97fa9235ec8c20d08acfbbb4e851e3"},
        {"80a5f6272031e18bb9bcd84f3385da65e7731b7039f13f5e3d475364cd4d42f7",
            "c0eccc384b44c88e92c57eb2d5ca4dfa",
            "6ed11741f724009a640a44fce7320954c46e18e0d7ae063bdbc8d7cf372709df"},
        {"cb1fc686c0eec11a89438b6f4013bf110e7171dace3297f3a657a309b3199629",
            "fcd49b93e5f8f299227e64d40dc864a3",
            "84b7e96937a1a0a406bb7162eeaad34308d49de60fd2f7ec9dc6a79cbab2ca34"},
        {"6640f4d80af5496ca1bc2cfff1fefbe99638dbceaabd7d0ade118999d45f053d",
            "31f59ceeeafdbfe8cae7914caeba90d6",
            "9af4697d2f5574a44834a2c2ae1a0505af9f5d869dbe381a994a18eb374c36a0"},
        {"0693ff36d971225a44ac92c092c60b399e672e4cc5aafd5e31426f123787ac27",
            "3a6293da061da405db45be1731d5fc4d",
            "f87b38609142c01095bfc425573bb3c698f9ae866b7e4216840b9c4caf3b0865"},
        {"809539bd2639a23bf83578700f055f313561c7785a4a19fc9114086915eee551",
            "780c65d6a3318e479c02141d3f0b3918",
            "902ea8ce4680c09395ce71874d242f84274243a156938aaa2dd37ac5be382b42"},
        {"1a170ddf25a4fd69b648926e6d794e73408805835c64b2c70efddd8cd1c56ce0",
            "05dbee10de87eb0c5acb2b66ebbe67d3",
            "a4e20b634c77d7db908d387b48ec2b370059db916e8ea7716dc07238532d5981"},
        {"3b354e4bb69b5b4a1126f509e84cad49f18c9f5f29f0be0c821316a6986e15a6",
            "d8a89af02f4b8b2901d8321796388b6c",
            "9816cb1a5b61993735a4b161b51ed2265b696e7ded5309c229a5a99f53534fbc"},
        {"4b9a818892e15a530db50dd2832e95ee192e5ed6afffb408bd624a0c4e12a081",
            "a9079c551de70501be0286d1bc78b045",
            "ebc5224cf41ea97473683b6c2f38a084bf6e1feaaeff62676db59d5b719d999b"},
        {"c49758f00003714c38f1d4972bde57ee8271f543b91e07ebce56b554eb7fa6a7",
            "31f0204e10cf4f2035f9e62bb5ba7303",
            "0dd8cc400f702d2c06ed920be52048a287076b86480ae273c6d568a2e9e7518c"}
    };

    // From libsodium's test/default/xchacha20.c (tv_stream_xchacha20)
    private static String[][] xChaCha20Tvs = {
        {"79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4",
            "b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419",
            "c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c"},
        {"ddf7784fee099612c40700862189d0397fcc4cc4b3cc02b5456b3a97d1186173",
            "a9a04491e7bf00c3ca91ac7c2d38a777d88993a7047dfcc4",
            "2f289d371f6f0abc3cb60d11d9b7b29adf6bc5ad843e8493e928448d"},
        {"3d12800e7b014e88d68a73f0a95b04b435719936feba60473f02a9e61ae60682",
            "56bed2599eac99fb27ebf4ffcb770a64772dec4d5849ea2d",
            "a2c3c1406f33c054a92760a8e0666b84f84fa3a618f0"},
        {"5f5763ff9a30c95da5c9f2a8dfd7cc6efd9dfb431812c075aa3e4f32e04f53e4",
            "a5fa890efa3b9a034d377926ce0e08ee6d7faccaee41b771",
            "8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a52b0b6a0f51891528f424c4a7f492"
                + "a8dd7bce8bac19fbdbe1fb379ac0"},
        {"eadc0e27f77113b5241f8ca9d6f9a5e7f09eee68d8a5cf30700563bf01060b4e",
            "a171a4ef3fde7c4794c5b86170dc5a099b478f1b852f7b64",
            "23839f61795c3cdbcee2c749a92543baeeea3cbb721402aa42e6cae140447575f2916c5d71108e3b13357e"
                + "af86f060cb"},
        {"91319c9545c7c804ba6b712e22294c386fe31c4ff3d278827637b959d3dbaab2",
            "410e854b2a911f174aaf1a56540fc3855851f41c65967a4e",
            "cbe7d24177119b7fdfa8b06ee04dade4256ba7d35ffda6b89f014e479faef6"},
        {"6a6d3f412fc86c4450fc31f89f64ed46baa3256ffcf8616e8c23a06c422842b6",
            "6b7773fce3c2546a5db4829f53a9165f41b08faae2fb72d5",
            "8b23e35b3cdd5f3f75525fc37960ec2b68918e8c046d8a832b9838f1546be662e54feb1203e2"},
        {"d45e56368ebc7ba9be7c55cfd2da0feb633c1d86cab67cd5627514fd20c2b391",
            "fd37da2db31e0c738754463edadc7dafb0833bd45da497fc",
            "47950efa8217e3dec437454bd6b6a80a287e2570f0a48b3fa1ea3eb868be3d486f6516606d85e5643becc4"
                + "73b370871ab9ef8e2a728f73b92bd98e6e26ea7c8ff96ec5a9e8de95e1eee9300c"},
        {"aface41a64a9a40cbc604d42bd363523bd762eb717f3e08fe2e0b4611eb4dcf3",
            "6906e0383b895ab9f1cf3803f42f27c79ad47b681c552c63",
            "a5fa7c0190792ee17675d52ad7570f1fb0892239c76d6e802c26b5b3544d13151e67513b8aaa1ac5af2d7f"
                + "d0d5e4216964324838"},
        {"9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232",
            "c047548266b7c370d33566a2425cbf30d82d1eaf5294109e",
            "a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c36"
                + "7888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e"
                + "6fae90fc31097cfc"},

    };

    @Override
    protected DjbCipher createInstance(byte[] key) {
      return DjbCipher.xChaCha20(key);
    }

    @Test
    public void testHChaCha20Tvs() {
      for (String[] tv : hChaCha20Tvs) {
        byte[] output = XChaCha20.hChaCha20(
            TestUtil.hexDecode(tv[0]), TestUtil.hexDecode(tv[1]));
        assertThat(TestUtil.hexEncode(output)).isEqualTo(tv[2]);
      }
    }

    @Test
    public void testXChaCha20Tvs() {
      for (String[] tv : xChaCha20Tvs) {
        ByteBuffer output = ByteBuffer.allocate(tv[2].length() / 2);
        byte[] inputZero = new byte[tv[2].length() / 2];
        DjbCipher cipher = createInstance(TestUtil.hexDecode(tv[0]));
        cipher.process(output, ByteBuffer.wrap(inputZero), TestUtil.hexDecode(tv[1]), 0);
        assertThat(TestUtil.hexEncode(output.array())).isEqualTo(tv[2]);
      }
    }
  }
}
