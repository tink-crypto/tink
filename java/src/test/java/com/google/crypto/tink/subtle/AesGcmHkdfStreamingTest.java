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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.TestUtil;
import com.google.crypto.tink.TestUtil.ByteBufferChannel;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.Reader;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for {@code AesGcmHkdfStreaming}-implementation of {@code StreamingAead}-primitive.
 */
@RunWith(JUnit4.class)
public class AesGcmHkdfStreamingTest {
  /**
   * TODO(bleichen): Some things that are not yet tested:
   *   - Thread-safety (i.e. operations should be atomic but more importantly
   *       the state must remain the same.
   *   - Reading beyond the end of the file
   *   - regression for c++ implementation
   */

  private boolean skipTestsWithLargerKeys;
  @Before
  public void setUp() throws Exception {
    if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
      System.out.println("WARNING: Unlimited Strength Jurisdiction Policy Files are required"
          + " but not installed. Skipping tests with keys larger than 128 bits.");
      skipTestsWithLargerKeys = true;
    } else {
      skipTestsWithLargerKeys = false;
    }
  }

  /**
   * Replacement for org.junit.Assert.assertEquals, since
   * org.junit.Assert.assertEquals is quite slow.
   */
  public void assertByteArrayEquals(String txt, byte[] expected, byte[] actual) throws Exception {
    assertEquals(txt + " arrays not of the same length", expected.length, actual.length);
    for (int i = 0; i < expected.length; i++) {
      if (expected[i] != actual[i]) {
        assertEquals(txt + " difference at position:" + i, expected[i], actual[i]);
      }
    }
  }

  public void assertByteArrayEquals(byte[] expected, byte[] actual) throws Exception {
    assertByteArrayEquals("", expected, actual);
  }

  /**
   * Checks whether the bytes from buffer.position() to buffer.limit() are the
   * same bytes as expected.
   */
  public void assertByteBufferContains(String txt, byte[] expected, ByteBuffer buffer)
      throws Exception {
    assertEquals(txt + " unexpected number of bytes in buffer", expected.length,
        buffer.remaining());
    byte[] content = new byte[buffer.remaining()];
    buffer.duplicate().get(content);
    assertByteArrayEquals(txt, expected, content);
  }

  public void assertByteBufferContains(byte[] expected, ByteBuffer buffer) throws Exception {
    assertByteBufferContains("", expected, buffer);
  }

  class PseudorandomReadableByteChannel implements ReadableByteChannel {
    private long size;
    private long position;
    private boolean open;
    private byte[] repeatedBlock;
    private static final int BLOCK_SIZE = 1024;

    public PseudorandomReadableByteChannel(long size) {
      this.size = size;
      this.position = 0;
      this.open = true;
      this.repeatedBlock = generatePlaintext(BLOCK_SIZE);
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
      if (!open) {
        throw new ClosedChannelException();
      }
      if (position == size) {
        return -1;
      }
      long start = position;
      long end = java.lang.Math.min(size, start + dst.remaining());
      long firstBlock = start / BLOCK_SIZE;
      long lastBlock = end / BLOCK_SIZE;
      int startOffset = (int) (start % BLOCK_SIZE);
      int endOffset = (int) (end % BLOCK_SIZE);
      if (firstBlock == lastBlock) {
        dst.put(repeatedBlock, startOffset, endOffset - startOffset);
      } else {
        dst.put(repeatedBlock, startOffset, BLOCK_SIZE - startOffset);
        for (long block = firstBlock + 1; block < lastBlock; block++) {
          dst.put(repeatedBlock);
        }
        dst.put(repeatedBlock, 0, endOffset);
      }
      position = end;
      return (int) (position - start);
    }

    @Override
    public void close() {
      this.open = false;
    }

    @Override
    public boolean isOpen() {
      return this.open;
    }
  }

  /**
   * Returns a plaintext of a given size.
   */
  private byte[] generatePlaintext(int size) {
    byte[] plaintext = new byte[size];
    for (int i = 0; i < size; i++) {
      plaintext[i] = (byte) (i % 253);
    }
    return plaintext;
  }

  private byte[] concatBytes(byte[] first, byte[] last) {
    byte[] res = new byte[first.length + last.length];
    java.lang.System.arraycopy(first, 0, res, 0, first.length);
    java.lang.System.arraycopy(last, 0, res, first.length, last.length);
    return res;
  }

  /**
   * Convenience method for encrypting some plaintext.
   * @param ags the streaming primitive
   * @param plaintext the plaintext to encrypt
   * @param aad the additional data to authenticate
   * @returns the ciphertext including a prefix of size ags.firstSegmentOffset
   */
  private byte[] encrypt(
      AesGcmHkdfStreaming ags,
      byte[] plaintext,
      byte[] aad) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    WritableByteChannel ctChannel = Channels.newChannel(bos);
    ctChannel.write(ByteBuffer.allocate(ags.getFirstSegmentOffset()));
    WritableByteChannel encChannel = ags.newEncryptingChannel(ctChannel, aad);
    encChannel.write(ByteBuffer.wrap(plaintext));
    encChannel.close();
    byte[] ciphertext = bos.toByteArray();
    long expectedSize = ags.expectedCiphertextSize(plaintext.length);
    assertEquals(expectedSize, ciphertext.length);
    return ciphertext;
  }

  private void isValidCiphertext(
      AesGcmHkdfStreaming ags,
      byte[] plaintext,
      byte[] aad,
      byte[] ciphertext) throws Exception {
    ByteBufferChannel ctChannel = new ByteBufferChannel(ciphertext);
    ctChannel.position(ags.getFirstSegmentOffset());
    ReadableByteChannel ptChannel = ags.newDecryptingChannel(ctChannel, aad);
    ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length + 1);
    ptChannel.read(decrypted);
    decrypted.flip();
    assertByteBufferContains(plaintext, decrypted);
  }

  /**
   * Encrypts and decrypts some plaintext in a stream and checks that the expected
   * plaintext is returned.
   * @param keySizeInBits the size of the AES key.
   * @param segmentSize the size of the ciphertext segments.
   * @param firstSegmentOffset number of bytes prepended to the ciphertext stream.
   * @param plaintextSize the size of the plaintext
   * @param chunkSize decryption read chunks of this size.
   */
  public void testEncryptDecrypt(
      int keySizeInBits,
      int segmentSize,
      int firstSegmentOffset,
      int plaintextSize,
      int chunkSize)
      throws Exception {
    if (keySizeInBits > 128 && skipTestsWithLargerKeys) {
      System.out.println("WARNING: skipping a test with key size over 128 bits.");
      return;
    }
    byte[] ikm =
        TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f112233445566778899aabbccddeeff");
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    AesGcmHkdfStreaming ags =
        new AesGcmHkdfStreaming(ikm, keySizeInBits, segmentSize, firstSegmentOffset);
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encrypt(ags, plaintext, aad);

    // Construct an InputStream from the ciphertext where the first
    // firstSegmentOffset bytes have already been read.
    ReadableByteChannel ctChannel =
        new ByteBufferChannel(ciphertext).position(firstSegmentOffset);

    // Construct an InputStream that returns the plaintext.
    ReadableByteChannel ptChannel = ags.newDecryptingChannel(ctChannel, aad);
    int decryptedSize = 0;
    while (true) {
      ByteBuffer chunk = ByteBuffer.allocate(chunkSize);
      int read = ptChannel.read(chunk);
      if (read == -1) {
        break;
      }
      assertEquals(read, chunk.position());
      byte[] expectedPlaintext =
          Arrays.copyOfRange(plaintext, decryptedSize, decryptedSize + read);
      assertByteArrayEquals(expectedPlaintext, Arrays.copyOf(chunk.array(), read));
      decryptedSize += read;
      // ptChannel should fill chunk, unless the end of the plaintext has been reached.
      if (decryptedSize < plaintextSize) {
        assertEquals("Decrypted chunk is shorter than expected\n" + ptChannel.toString(),
                     chunk.limit(), chunk.position());
      }
    }
    assertEquals(plaintext.length, decryptedSize);
  }

  /**
   * Encrypt and then decrypt partially, and check that the result is the same.
   */
  public void testEncryptDecryptRandomAccess(
      int keySizeInBits, int segmentSize, int firstSegmentOffset, int plaintextSize)
      throws Exception {
    if (keySizeInBits > 128 && skipTestsWithLargerKeys) {
      System.out.println("WARNING: skipping a test with key size over 128 bits.");
      return;
    }
    byte[] ikm =
        TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f112233445566778899aabbccddeeff");
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    AesGcmHkdfStreaming ags =
        new AesGcmHkdfStreaming(ikm, keySizeInBits, segmentSize, firstSegmentOffset);
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encrypt(ags, plaintext, aad);

    // Construct a channel with random access for the ciphertext.
    ByteBufferChannel bbc = new ByteBufferChannel(ciphertext);
    SeekableByteChannel ptChannel = ags.newSeekableDecryptingChannel(bbc, aad);

    for (int start = 0; start < plaintextSize; start += 1 + start / 2) {
      for (int length = 1; length < plaintextSize; length += 1 + length / 2) {
        ByteBuffer pt = ByteBuffer.allocate(length);
        ptChannel.position(start);
        int read = ptChannel.read(pt);
        // Expect that pt is filled unless the end of the plaintext has been reached.
        assertTrue("start:" + start + " read:" + read + " length:" + length,
                    pt.remaining() == 0 || start + pt.position() == plaintext.length);
        String expected =
            TestUtil.hexEncode(Arrays.copyOfRange(plaintext, start, start + pt.position()));
        String actual = TestUtil.hexEncode(Arrays.copyOf(pt.array(), pt.position()));
        assertEquals("start: " + start, expected, actual);
      }
    }
  }

  /* The ciphertext is smaller than 1 segment */
  @Test
  public void testEncryptDecryptSmall() throws Exception {
    testEncryptDecrypt(128, 256, 0, 20, 64);
    testEncryptDecrypt(128, 512, 0, 400, 64);
  }

  /* The ciphertext has a non-zero offset */
  @Test
  public void testEncryptDecryptSmallWithOffset() throws Exception {
    testEncryptDecrypt(128, 256, 8, 20, 64);
    testEncryptDecrypt(128, 512, 8, 400, 64);
  }

  /* Empty plaintext */
  @Test
  public void testEncryptDecryptEmpty() throws Exception {
    testEncryptDecrypt(128, 256, 0, 0, 128);
    testEncryptDecrypt(128, 256, 8, 0, 128);
  }

  /* The ciphertext contains more than 1 segment. */
  @Test
  public void testEncryptDecryptMedium() throws Exception {
    testEncryptDecrypt(128, 256, 0, 1024, 128);
    testEncryptDecrypt(128, 512, 0, 3086, 128);
    testEncryptDecrypt(256, 1024, 0, 12345, 128);
  }

  /* During decryption large plaintext chunks are requested */
  @Test
  public void testEncryptDecryptLargeChunks() throws Exception {
    testEncryptDecrypt(128, 256, 0, 1024, 4096);
    testEncryptDecrypt(128, 512, 0, 5086, 4096);
    testEncryptDecrypt(256, 1024, 0, 12345, 5000);
  }

  @Test
  public void testEncryptDecryptMediumWithOffset() throws Exception {
    testEncryptDecrypt(128, 256, 8, 1024, 64);
    testEncryptDecrypt(128, 512, 20, 3086, 256);
    testEncryptDecrypt(256, 1024, 10, 12345, 5000);
  }

  /* The ciphertext ends at a segment boundary. */
  @Test
  public void testEncryptDecryptLastSegmentFull() throws Exception {
    testEncryptDecrypt(128, 256, 0, 216, 64);
    testEncryptDecrypt(128, 256, 16, 200, 256);
    testEncryptDecrypt(128, 256, 16, 440, 1024);
  }

  /* The ciphertext is smaller than 1 segment. */
  @Test
  public void testEncryptDecryptRandomAccessSmall() throws Exception {
    testEncryptDecryptRandomAccess(128, 256, 0, 100);
    testEncryptDecryptRandomAccess(128, 512, 0, 400);
  }

  @Test
  public void testEncryptDecryptRandomAccessSmallWithOffset() throws Exception {
    testEncryptDecryptRandomAccess(128, 256, 8, 20);
    testEncryptDecryptRandomAccess(128, 256, 8, 100);
    testEncryptDecryptRandomAccess(128, 512, 8, 400);
  }

  /* Empty plaintext */
  @Test
  public void testEncryptDecryptRandomAccessEmpty() throws Exception {
    testEncryptDecryptRandomAccess(128, 256, 0, 0);
    testEncryptDecryptRandomAccess(128, 256, 8, 0);
  }

  @Test
  public void testEncryptDecryptRandomAccessMedium() throws Exception {
    testEncryptDecryptRandomAccess(128, 256, 0, 2048);
    testEncryptDecryptRandomAccess(128, 256, 0, 4096);
    testEncryptDecryptRandomAccess(256, 1024, 0, 12345);
  }

  @Test
  public void testEncryptDecryptRandomAccessMediumWithOffset() throws Exception {
    testEncryptDecryptRandomAccess(128, 256, 8, 2048);
    testEncryptDecryptRandomAccess(128, 256, 10, 4096);
    testEncryptDecryptRandomAccess(256, 1024, 20, 12345);
    testEncryptDecryptRandomAccess(128, 4096, 0, 123456);
  }

  /* The ciphertext ends at a segment boundary. */
  @Test
  public void testEncryptDecryptRandomAccessLastSegmentFull() throws Exception {
    testEncryptDecryptRandomAccess(128, 256, 0, 216);
    testEncryptDecryptRandomAccess(128, 256, 16, 200);
    testEncryptDecryptRandomAccess(128, 256, 16, 440);
  }

  /**
   * Encrypts and decrypts a with non-ASCII characters using CharsetEncoders
   * and CharsetDecoders.
   */
  @Test
  public void testEncryptDecryptString() throws Exception {
    int segmentSize = 512;
    int firstSegmentOffset = 0;
    int keySizeInBits = 128;
    byte[] ikm =
        TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f112233445566778899aabbccddeeff");
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    AesGcmHkdfStreaming ags =
        new AesGcmHkdfStreaming(ikm, keySizeInBits, segmentSize, firstSegmentOffset);

    String stringWithNonAsciiChars = "αβγδ áéíóúý ∀∑∊∫≅⊕⊄";
    int repetitions = 1000;

    // Encrypts a sequence of strings.
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    WritableByteChannel ctChannel = Channels.newChannel(bos);
    Writer writer = Channels.newWriter(ags.newEncryptingChannel(ctChannel, aad), "UTF-8");
    for (int i = 0; i < repetitions; i++) {
      writer.write(stringWithNonAsciiChars);
    }
    writer.close();
    byte[] ciphertext = bos.toByteArray();

    // Decrypts a sequence of strings.
    // channels.newReader does not always return the requested number of characters.
    ByteBufferChannel ctBuffer = new ByteBufferChannel(ByteBuffer.wrap(ciphertext));
    Reader reader = Channels.newReader(ags.newSeekableDecryptingChannel(ctBuffer, aad), "UTF-8");
    for (int i = 0; i < repetitions; i++) {
      char[] chunk = new char[stringWithNonAsciiChars.length()];
      int position = 0;
      while (position < stringWithNonAsciiChars.length()) {
        int read = reader.read(chunk, position, stringWithNonAsciiChars.length() - position);
        assertTrue("read:" + read,  read > 0);
        position += read;
      }
      assertEquals("i:" + i, stringWithNonAsciiChars, new String(chunk));
    }
    int res = reader.read();
    assertEquals(-1, res);
  }

  /**
   * Test encryption with a simulated ciphertext channel, which has only
   * a limited capacity.
   */
  @Test
  public void testEncryptLimitedCiphertextChannel() throws Exception {
    int plaintextSize = 1 << 15;
    int maxChunkSize = 100;
    int segmentSize = 512;
    int firstSegmentOffset = 0;
    int keySizeInBits = 128;
    byte[] ikm =
        TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f112233445566778899aabbccddeeff");
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    AesGcmHkdfStreaming ags =
        new AesGcmHkdfStreaming(ikm, keySizeInBits, segmentSize, firstSegmentOffset);
    byte[] plaintext = generatePlaintext(plaintextSize);
    int ciphertextLength = (int) ags.expectedCiphertextSize(plaintextSize);
    ByteBuffer ciphertext = ByteBuffer.allocate(ciphertextLength);
    WritableByteChannel ctChannel = new ByteBufferChannel(ciphertext, maxChunkSize);
    WritableByteChannel encChannel = ags.newEncryptingChannel(ctChannel, aad);
    ByteBuffer plaintextBuffer = ByteBuffer.wrap(plaintext);
    int loops = 0;
    while (plaintextBuffer.remaining() > 0) {
      encChannel.write(plaintextBuffer);
      loops += 1;
      if (loops > 100000) {
        System.out.println(encChannel.toString());
        fail("Too many loops");
      }
    }
    encChannel.close();
    assertFalse(encChannel.isOpen());
    isValidCiphertext(ags, plaintext, aad, ciphertext.array());
  }

  /**
   * Tries to decrypt a modified ciphertext.
   * Each call to read must either return the original plaintext
   * (e.g. when the modification in the ciphertext has not yet been read)
   * or it must throw an IOException.
   */
  private void tryDecryptModifiedCiphertext(
      AesGcmHkdfStreaming ags,
      byte[] modifiedCiphertext,
      byte[] aad,
      int chunkSize,
      byte[] plaintext) throws Exception {
    ByteBufferChannel ct = new ByteBufferChannel(modifiedCiphertext);
    ct.position(ags.getFirstSegmentOffset());
    ReadableByteChannel ptChannel = ags.newDecryptingChannel(ct, aad);
    int position = 0;
    int read;
    do {
      ByteBuffer chunk = ByteBuffer.allocate(chunkSize);
      try {
        read = ptChannel.read(chunk);
      } catch (IOException ex) {
        // Detected that the ciphertext was modified.
        // TODO(bleichen): Maybe check that the stream cannot longer be accessed.
        return;
      }
      if (read > 0) {
        assertTrue("Read more plaintext than expected", position + read <= plaintext.length);
        // Everything decrypted must be equal to the original plaintext.
        assertByteArrayEquals(
            "Returned modified plaintext position:" + position + " size:" + read,
            Arrays.copyOf(chunk.array(), read),
            Arrays.copyOfRange(plaintext, position, position + read));
        position += read;
      }
    } while (read >= 0);
    fail("Reached end of plaintext.");
  }

  // Modifies the ciphertext. Checks that decryption either results in correct plaintext
  // or an exception.
  // The following modifications are tested:
  // (1) truncate ciphertext
  // (2) append stuff
  // (3) flip bits
  // (4) remove segments
  // (5) duplicate segments
  // (6) modify aad
  @Test
  public void testModifiedCiphertext() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 128;
    int segmentSize = 256;
    int offset = 8;
    int plaintextSize = 512;
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, keySize, segmentSize, offset);
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encrypt(ags, plaintext, aad);

    // truncate the ciphertext
    for (int i = 0; i < ciphertext.length; i += 8) {
      byte[] truncatedCiphertext = Arrays.copyOf(ciphertext, i);
      tryDecryptModifiedCiphertext(ags, truncatedCiphertext, aad, 128, plaintext);
    }

    // Append stuff to ciphertext
    int[] sizes = new int[]{1, (segmentSize - ciphertext.length % segmentSize), segmentSize};
    for (int appendedBytes : sizes) {
      byte [] modifiedCiphertext = concatBytes(ciphertext, new byte[appendedBytes]);
      tryDecryptModifiedCiphertext(ags, modifiedCiphertext, aad, 128, plaintext);
    }

    // flip bits
    for (int pos = offset; pos < ciphertext.length; pos++) {
      byte[] modifiedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);
      modifiedCiphertext[pos] ^= (byte) 1;
      tryDecryptModifiedCiphertext(ags, modifiedCiphertext, aad, 128, plaintext);
    }

    // delete segments
    for (int segment = 0; segment < (ciphertext.length / segmentSize); segment++) {
      byte[] modifiedCiphertext =
          concatBytes(
              Arrays.copyOf(ciphertext, segment * segmentSize),
              Arrays.copyOfRange(ciphertext, (segment + 1) * segmentSize, ciphertext.length));
      tryDecryptModifiedCiphertext(ags, modifiedCiphertext, aad, 128, plaintext);
    }

    // duplicate segments
    for (int segment = 0; segment < (ciphertext.length / segmentSize); segment++) {
      byte[] modifiedCiphertext =
          concatBytes(Arrays.copyOf(ciphertext, (segment + 1) * segmentSize),
                      Arrays.copyOfRange(ciphertext, segment * segmentSize, ciphertext.length));
      tryDecryptModifiedCiphertext(ags, modifiedCiphertext, aad, 128, plaintext);
    }

    // Modify aad
    // When the additional data is modified then any attempt to read plaintext must fail.
    for (int pos = 0; pos < aad.length; pos++) {
      byte[] modifiedAad = Arrays.copyOf(aad, aad.length);
      modifiedAad[pos] ^= (byte) 1;
      tryDecryptModifiedCiphertext(ags, ciphertext, modifiedAad, 128, new byte[0]);
    }
  }

  /**
   * Tries to decrypt a modified ciphertext using an SeekableByteChannel.
   * Each call to read must either return the original plaintext
   * (e.g. when the modification in the ciphertext does not affect the plaintext)
   * or it must throw an IOException.
   */
  private void tryDecryptModifiedCiphertextWithSeekableByteChannel(
      AesGcmHkdfStreaming ags,
      byte[] modifiedCiphertext,
      byte[] aad,
      byte[] plaintext) throws Exception {

    ByteBufferChannel bbc = new ByteBufferChannel(modifiedCiphertext);
    SeekableByteChannel ptChannel;
    // Failing in the constructor is valid in principle, but does not happen
    // with the current implementation. Hence we don't catch these exceptions at the moment.
    try {
      ptChannel = ags.newSeekableDecryptingChannel(bbc, aad);
    } catch (IOException | GeneralSecurityException ex) {
      return;
    }
    for (int start = 0; start <= plaintext.length; start += 1 + start / 2) {
      for (int length = 1; length <= plaintext.length; length += 1 + length / 2) {
        ByteBuffer pt = ByteBuffer.allocate(length);
        ptChannel.position(start);
        int read;
        try {
          read = ptChannel.read(pt);
        } catch (IOException ex) {
          // Modified ciphertext was found.
          // TODO(bleichen): Currently it is undefined whether we should be able to read
          //   more plaintext from the stream (i.e. unmodified segments).
          //   However, if later calls return plaintext this has to be valid plaintext.
          continue;
        }
        if (read == -1) {
          // ptChannel claims that we reached the end of the plaintext.
          assertTrue("Incorrect truncation: ", start == plaintext.length);
        } else {
          // Expect the decrypted plaintext not to be longer than the expected plaintext.
          assertTrue("start:" + start + " read:" + read + " length:" + length,
                     start + read <= plaintext.length);
          // Check that the decrypted plaintext matches the original plaintext.
          String expected =
              TestUtil.hexEncode(Arrays.copyOfRange(plaintext, start, start + pt.position()));
          String actual = TestUtil.hexEncode(Arrays.copyOf(pt.array(), pt.position()));
          assertEquals("start: " + start, expected, actual);
        }
      }
    }
  }

  @Test
  public void testModifiedCiphertextWithSeekableByteChannel() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 128;
    int segmentSize = 256;
    int offset = 8;
    int plaintextSize = 2000;
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, keySize, segmentSize, offset);
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encrypt(ags, plaintext, aad);

    // truncate the ciphertext
    for (int i = 0; i < ciphertext.length; i += 64) {
      byte[] truncatedCiphertext = Arrays.copyOf(ciphertext, i);
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, truncatedCiphertext, aad, plaintext);
    }

    // Append stuff to ciphertext
    int[] sizes = new int[]{1, (segmentSize - ciphertext.length % segmentSize), segmentSize};
    for (int appendedBytes : sizes) {
      byte [] modifiedCiphertext = concatBytes(ciphertext, new byte[appendedBytes]);
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, modifiedCiphertext, aad, plaintext);
    }

    // flip bits
    for (int pos = offset; pos < ciphertext.length; pos++) {
      byte[] modifiedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);
      modifiedCiphertext[pos] ^= (byte) 1;
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, modifiedCiphertext, aad, plaintext);
    }

    // delete segments
    for (int segment = 0; segment < (ciphertext.length / segmentSize); segment++) {
      byte[] modifiedCiphertext =
          concatBytes(Arrays.copyOf(ciphertext, segment * segmentSize),
                      Arrays.copyOfRange(
                          ciphertext, (segment + 1) * segmentSize, ciphertext.length));
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, modifiedCiphertext, aad, plaintext);
    }

    // duplicate segments
    for (int segment = 0; segment < (ciphertext.length / segmentSize); segment++) {
      byte[] modifiedCiphertext =
          concatBytes(Arrays.copyOf(ciphertext, (segment + 1) * segmentSize),
                      Arrays.copyOfRange(ciphertext, segment * segmentSize, ciphertext.length));
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, modifiedCiphertext, aad, plaintext);
    }

    // Modify aad
    // When the additional data is modified then any attempt to read plaintext must fail.
    for (int pos = 0; pos < aad.length; pos++) {
      byte[] modifiedAad = Arrays.copyOf(aad, aad.length);
      modifiedAad[pos] ^= (byte) 1;
      tryDecryptModifiedCiphertextWithSeekableByteChannel(
          ags, ciphertext, modifiedAad, new byte[0]);
    }
  }

  /**
   * Reads everything from plaintext, encrypt it and writes the result to ciphertext.
   * This method is used to test aynchronous encryption.
   * @param ags the streaming encryption
   * @param plaintext the channel containing the plaintext
   * @param ciphertext the channel to which the ciphertext is written
   * @param aad the additional data to authenticate
   * @param chuckSize the size of blocks that are read and written. This size determines the
   *        temporary memory used in this method but is independent of the streaming encryption.
   * @throws RuntimeException if something goes wrong.
   */
  private void encryptChannel(
      AesGcmHkdfStreaming ags,
      ReadableByteChannel plaintext,
      WritableByteChannel ciphertext,
      byte[] aad,
      int chunkSize) {
    try {
      WritableByteChannel encChannel = ags.newEncryptingChannel(ciphertext, aad);
      ByteBuffer chunk = ByteBuffer.allocate(chunkSize);
      int read;
      do {
        chunk.clear();
        read = plaintext.read(chunk);
        if (read > 0) {
          chunk.flip();
          encChannel.write(chunk);
        }
      } while (read != -1);
      encChannel.close();
    } catch (Exception ex) {
      // TODO(bleichen): What is the best way to chatch exceptions in threads?
      throw new java.lang.RuntimeException(ex);
    }
  }

  /**
   * Constructs a ReadableByteChannel with ciphertext from a ReadableByteChannel.
   * The method constructs a new thread that is used to encrypt the plaintext.
   * TODO(bleichen): Using PipedInputStream may have performance problems.
   */
  private ReadableByteChannel ciphertextChannel(
      final AesGcmHkdfStreaming ags,
      final ReadableByteChannel plaintext,
      final byte[] aad,
      final int chunkSize) throws Exception {
    PipedOutputStream output = new PipedOutputStream();
    PipedInputStream result = new PipedInputStream(output);
    final WritableByteChannel ciphertext = Channels.newChannel(output);
    new Thread(new Runnable() {
      public void run() {
        encryptChannel(ags, plaintext, ciphertext, aad, chunkSize);
      }
    }).start();
    return Channels.newChannel(result);
  }

  /**
   * Encrypt and decrypt a long ciphertext.
   */
  @Test
  public void testEncryptDecryptLong() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 128;
    int segmentSize = 1 << 20;
    long plaintextSize = (1L << 32) + 1234567;
    int offset = 0;
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, keySize, segmentSize, offset);
    ReadableByteChannel plaintext = new PseudorandomReadableByteChannel(plaintextSize);
    ReadableByteChannel copy = new PseudorandomReadableByteChannel(plaintextSize);
    ReadableByteChannel ciphertext = ciphertextChannel(ags, plaintext, aad, 1 << 20);
    ReadableByteChannel decrypted = ags.newDecryptingChannel(ciphertext, aad);
    byte[] chunk = new byte[1 << 15];
    int read;
    long decryptedBytes = 0;
    do {
      read = decrypted.read(ByteBuffer.wrap(chunk));
      if (read > 0) {
        ByteBuffer expected = ByteBuffer.allocate(read);
        int cnt = copy.read(expected);
        decryptedBytes += read;
        assertByteArrayEquals(expected.array(), Arrays.copyOf(chunk, read));
      }
    } while (read != -1);
    assertEquals(plaintextSize, decryptedBytes);
  }

  /**
   * Encrypt some plaintext to a file, then decrypt from the file
   */
  @Test
  public void testFileEncrytion() throws Exception {
    int plaintextSize = 1 << 18;
    ByteBufferChannel plaintext = new ByteBufferChannel(generatePlaintext(plaintextSize));
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 128;
    int segmentSize = 4096;
    int offset = 0;
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, keySize, segmentSize, offset);

    // Encrypt to file
    Path path = TestUtil.generateRandomPath("testFileEncryption");
    FileChannel ctChannel =
        FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    WritableByteChannel bc = ags.newEncryptingChannel(ctChannel, aad);
    int chunkSize = 1000;
    ByteBuffer chunk = ByteBuffer.allocate(chunkSize);
    int read;
    do {
      chunk.clear();
      read = plaintext.read(chunk);
      if (read > 0) {
        chunk.flip();
        bc.write(chunk);
      }
    } while (read != -1);
    bc.close();

    // Decrypt the whole file and compare to plaintext
    plaintext.rewind();
    ctChannel = FileChannel.open(path, java.nio.file.StandardOpenOption.READ);
    ReadableByteChannel ptStream = ags.newDecryptingChannel(ctChannel, aad);
    int decryptedSize = 0;
    do {
      ByteBuffer decrypted = ByteBuffer.allocate(512);
      read = ptStream.read(decrypted);
      if (read > 0) {
        ByteBuffer expected = ByteBuffer.allocate(read);
        plaintext.read(expected);
        decrypted.flip();
        assertByteBufferContains(expected.array(), decrypted);
        decryptedSize += read;
      }
    } while (read != -1);
    assertEquals(plaintextSize, decryptedSize);

    // Decrypt file partially using FileChannel and compare to plaintext
    plaintext.rewind();
    ctChannel = FileChannel.open(path, java.nio.file.StandardOpenOption.READ);
    SeekableByteChannel ptChannel = ags.newSeekableDecryptingChannel(ctChannel, aad);
    SecureRandom random = new SecureRandom();
    for (int samples = 0; samples < 100; samples++) {
      int start = random.nextInt(plaintextSize);
      int length = random.nextInt(plaintextSize / 100);
      ByteBuffer decrypted = ByteBuffer.allocate(length);
      ptChannel.position(start);
      read = ptChannel.read(decrypted);
      // We expect that all read of ctChannel return the requested number of bytes.
      // Hence we also expect that ptChannel returns the maximal number of bytes.
      if (read < length && read + start < plaintextSize) {
        fail("Plaintext size is smaller than expected; read:" + read + " position:" + start
             + " length:" + length);
      }
      byte[] expected = new byte[read];
      plaintext.position(start);
      plaintext.read(ByteBuffer.wrap(expected));
      decrypted.flip();
      assertByteBufferContains(expected, decrypted);
    }
  }
}
