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
// See the License for the specified language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.subtle.Random;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.Reader;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/** Helpers for streaming tests. */
public class StreamingTestUtil {
  /**
   * Implements a SeekableByteChannel for testing.
   *
   * <p>The implementation is backed by a ByteBuffer.
   */
  public static class ByteBufferChannel implements SeekableByteChannel {
    private final ByteBuffer buffer;

    /**
     * Defines the maximal size of a chunk that is transferred with a single write. This can be used
     * to test the behavior of streaming encryption with channels where not always sufficiently many
     * bytes are available during reads and writes.
     */
    private final int maxChunkSize;

    /** keeps track whether the channel is still open. */
    private boolean isopen;

    public ByteBufferChannel(ByteBuffer buffer) {
      this.buffer = buffer.duplicate();
      maxChunkSize = java.lang.Integer.MAX_VALUE;
      isopen = true;
    }

    public ByteBufferChannel(ByteBuffer buffer, int maxChunkSize) {
      this.buffer = buffer.duplicate();
      this.maxChunkSize = maxChunkSize;
      isopen = true;
    }

    public ByteBufferChannel(byte[] bytes) {
      this.buffer = ByteBuffer.wrap(bytes);
      maxChunkSize = java.lang.Integer.MAX_VALUE;
      isopen = true;
    }

    private void checkIsOpen() throws ClosedChannelException {
      if (!isopen) {
        throw new ClosedChannelException();
      }
    }

    @Override
    public long position() throws ClosedChannelException {
      checkIsOpen();
      return buffer.position();
    }

    @Override
    public synchronized ByteBufferChannel position(long newPosition) throws ClosedChannelException {
      checkIsOpen();
      if (newPosition < 0) {
        throw new IllegalArgumentException("negative position");
      }
      if (newPosition > buffer.limit()) {
        newPosition = buffer.limit();
      }
      buffer.position((int) newPosition);
      return this;
    }

    @Override
    public synchronized int read(ByteBuffer dst) throws IOException {
      checkIsOpen();
      if (buffer.remaining() == 0) {
        return -1;
      }
      // Not the most efficient way.
      int size = Math.min(buffer.remaining(), dst.remaining());
      size = Math.min(size, maxChunkSize);
      byte[] bytes = new byte[size];
      buffer.get(bytes);
      dst.put(bytes);
      return size;
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
      checkIsOpen();
      // not the most efficient way
      int size = Math.min(buffer.remaining(), src.remaining());
      size = Math.min(size, maxChunkSize);
      byte[] bytes = new byte[size];
      src.get(bytes);
      buffer.put(bytes);
      return size;
    }

    @Override
    public long size() throws ClosedChannelException {
      checkIsOpen();
      return buffer.limit();
    }

    @Override
    public SeekableByteChannel truncate(long size) throws NonWritableChannelException {
      throw new NonWritableChannelException();
    }

    @Override
    public void close() throws IOException {
      isopen = false;
    }

    @Override
    public boolean isOpen() {
      return isopen;
    }

    public void rewind() {
      isopen = true;
      buffer.rewind();
    }
  }

  /**
   * Implements a ReadableByteChannel for testing.
   *
   * <p>The implementation is backed by an array of bytes of size {@code BLOCK_SIZE}, which upon
   * read()-operation is repeated until the specified size of the channel.
   */
  public static class PseudorandomReadableByteChannel implements ReadableByteChannel {
    private long size;
    private long position;
    private boolean open;
    private byte[] repeatedBlock;
    public static final int BLOCK_SIZE = 1024;

    /** Returns a plaintext of a given size. */
    private byte[] generatePlaintext(int size) {
      byte[] plaintext = new byte[size];
      for (int i = 0; i < size; i++) {
        plaintext[i] = (byte) (i % 253);
      }
      return plaintext;
    }

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

  /** Returns a plaintext of a given size. */
  public static byte[] generatePlaintext(int size) {
    byte[] plaintext = new byte[size];
    for (int i = 0; i < size; i++) {
      plaintext[i] = (byte) (i % 253);
    }
    return plaintext;
  }

  public static byte[] concatBytes(byte[] first, byte[] last) {
    byte[] res = new byte[first.length + last.length];
    java.lang.System.arraycopy(first, 0, res, 0, first.length);
    java.lang.System.arraycopy(last, 0, res, first.length, last.length);
    return res;
  }

  /**
   * Tests encryption and decryption functionalities using {@code encryptionStreamingAead} for
   * encryption and {@code decryptionStreamingAead} for decryption.
   */
  public static void testEncryptionAndDecryption(
      StreamingAead encryptionStreamingAead, StreamingAead decryptionStreamingAead)
      throws Exception {
    byte[] aad = Random.randBytes(15);
    // Short plaintext.
    byte[] shortPlaintext = Random.randBytes(10);
    testEncryptionAndDecryption(
        encryptionStreamingAead, decryptionStreamingAead, shortPlaintext, aad);
    // Long plaintext.
    byte[] longPlaintext = Random.randBytes(1100);
    testEncryptionAndDecryption(
        encryptionStreamingAead, decryptionStreamingAead, longPlaintext, aad);
  }

  /** Tests encryption and decryption functionalities of {@code streamingAead}. */
  public static void testEncryptionAndDecryption(StreamingAead streamingAead) throws Exception {
    testEncryptionAndDecryption(streamingAead, streamingAead);
  }

  /**
   * Tests encryption and decryption functionalities using {@code encryptionStreamingAead} for
   * encryption and {@code decryptionStreamingAead} for decryption on inputs {@code plaintext} and
   * {@code aad}.
   */
  public static void testEncryptionAndDecryption(
      StreamingAead encryptionStreamingAead,
      StreamingAead decryptionStreamingAead,
      byte[] plaintext,
      byte[] aad)
      throws Exception {

    // Encrypt plaintext.
    ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
    WritableByteChannel encChannel =
        encryptionStreamingAead.newEncryptingChannel(Channels.newChannel(ciphertext), aad);
    encChannel.write(ByteBuffer.wrap(plaintext));
    encChannel.close();

    // Decrypt ciphertext via ReadableByteChannel.
    {
      ByteBufferChannel ciphertextChannel = new ByteBufferChannel(ciphertext.toByteArray());
      ReadableByteChannel decChannel =
          decryptionStreamingAead.newDecryptingChannel(ciphertextChannel, aad);
      ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length);
      int unused = decChannel.read(decrypted);

      // Compare results;
      TestUtil.assertByteArrayEquals(plaintext, decrypted.array());
    }

    // Decrypt ciphertext via SeekableByteChannel.
    {
      ByteBufferChannel ciphertextChannel = new ByteBufferChannel(ciphertext.toByteArray());
      SeekableByteChannel decChannel =
          decryptionStreamingAead.newSeekableDecryptingChannel(ciphertextChannel, aad);
      ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length);
      int unused = decChannel.read(decrypted);

      // Compare results;
      TestUtil.assertByteArrayEquals(plaintext, decrypted.array());
    }
  }

  /**
   * Convenience method for encrypting some plaintext.
   *
   * @param ags the streaming primitive
   * @param plaintext the plaintext to encrypt
   * @param aad the additional data to authenticate
   * @param firstSegmentOffset the offset of the first ciphertext segment
   * @return the ciphertext including a prefix of size ags.firstSegmentOffset
   */
  public static byte[] encrypt(
      StreamingAead ags, byte[] plaintext, byte[] aad, int firstSegmentOffset) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    WritableByteChannel ctChannel = Channels.newChannel(bos);
    ctChannel.write(ByteBuffer.allocate(firstSegmentOffset));
    WritableByteChannel encChannel = ags.newEncryptingChannel(ctChannel, aad);
    encChannel.write(ByteBuffer.wrap(plaintext));
    encChannel.close();
    byte[] ciphertext = bos.toByteArray();
    return ciphertext;
  }

  /**
   * Encrypts and decrypts some plaintext in a stream and checks that the expected plaintext is
   * returned.
   */
  public static void testEncryptDecrypt(
      StreamingAead ags, int firstSegmentOffset, int plaintextSize, int chunkSize)
      throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encrypt(ags, plaintext, aad, firstSegmentOffset);

    // Construct an InputStream from the ciphertext where the first
    // firstSegmentOffset bytes have already been read.
    ReadableByteChannel ctChannel = new ByteBufferChannel(ciphertext).position(firstSegmentOffset);

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
      byte[] expectedPlaintext = Arrays.copyOfRange(plaintext, decryptedSize, decryptedSize + read);
      TestUtil.assertByteArrayEquals(expectedPlaintext, Arrays.copyOf(chunk.array(), read));
      decryptedSize += read;
      // ptChannel should fill chunk, unless the end of the plaintext has been reached.
      if (decryptedSize < plaintextSize) {
        assertEquals(
            "Decrypted chunk is shorter than expected\n" + ptChannel.toString(),
            chunk.limit(),
            chunk.position());
      }
    }
    assertEquals(plaintext.length, decryptedSize);
  }

  /** Encrypt and then decrypt partially, and check that the result is the same. */
  public static void testEncryptDecryptRandomAccess(
      StreamingAead ags, int firstSegmentOffset, int plaintextSize) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encrypt(ags, plaintext, aad, firstSegmentOffset);

    // Construct a channel with random access for the ciphertext.
    ByteBufferChannel bbc = new ByteBufferChannel(ciphertext);
    SeekableByteChannel ptChannel = ags.newSeekableDecryptingChannel(bbc, aad);

    for (int start = 0; start < plaintextSize; start += 1 + start / 2) {
      for (int length = 1; length < plaintextSize; length += 1 + length / 2) {
        ByteBuffer pt = ByteBuffer.allocate(length);
        ptChannel.position(start);
        int read = ptChannel.read(pt);
        // Expect that pt is filled unless the end of the plaintext has been reached.
        assertTrue(
            "start:" + start + " read:" + read + " length:" + length,
            pt.remaining() == 0 || start + pt.position() == plaintext.length);
        String expected =
            TestUtil.hexEncode(Arrays.copyOfRange(plaintext, start, start + pt.position()));
        String actual = TestUtil.hexEncode(Arrays.copyOf(pt.array(), pt.position()));
        assertEquals("start: " + start, expected, actual);
      }
    }
  }

  public static void testEncryptSingleBytes(StreamingAead ags, int plaintextSize) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    byte[] plaintext = generatePlaintext(plaintextSize);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    WritableByteChannel ctChannel = Channels.newChannel(bos);
    WritableByteChannel encChannel = ags.newEncryptingChannel(ctChannel, aad);
    OutputStream encStream = Channels.newOutputStream(encChannel);
    for (int i = 0; i < plaintext.length; i++) {
      encStream.write(plaintext[i]);
    }
    encStream.close();
    isValidCiphertext(ags, plaintext, aad, bos.toByteArray());
  }

  /**
   * Encrypts and decrypts a with non-ASCII characters using CharsetEncoders and CharsetDecoders.
   */
  public static void testEncryptDecryptString(StreamingAead ags) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
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
        assertTrue("read:" + read, read > 0);
        position += read;
      }
      assertEquals("i:" + i, stringWithNonAsciiChars, new String(chunk));
    }
    int res = reader.read();
    assertEquals(-1, res);
  }

  public static void isValidCiphertext(
      StreamingAead ags, byte[] plaintext, byte[] aad, byte[] ciphertext) throws Exception {
    ByteBufferChannel ctChannel = new ByteBufferChannel(ciphertext);
    ReadableByteChannel ptChannel = ags.newDecryptingChannel(ctChannel, aad);
    ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length + 1);
    ptChannel.read(decrypted);
    decrypted.flip();
    TestUtil.assertByteBufferContains(plaintext, decrypted);
  }

  /**
   * Tries to decrypt a modified ciphertext. Each call to read must either return the original
   * plaintext (e.g. when the modification in the ciphertext has not yet been read) or it must throw
   * an IOException.
   */
  private static void tryDecryptModifiedCiphertext(
      StreamingAead ags,
      int firstSegmentOffset,
      byte[] modifiedCiphertext,
      byte[] aad,
      int chunkSize,
      byte[] plaintext)
      throws Exception {
    ByteBufferChannel ct = new ByteBufferChannel(modifiedCiphertext);
    ct.position(firstSegmentOffset);
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
        TestUtil.assertByteArrayEquals(
            "Returned modified plaintext position:" + position + " size:" + read,
            Arrays.copyOf(chunk.array(), read),
            Arrays.copyOfRange(plaintext, position, position + read));
        position += read;
      }
    } while (read >= 0);
    fail("Reached end of plaintext.");
  }

  public static void testModifiedCiphertext(
      StreamingAead ags, int segmentSize, int firstSegmentOffset) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    int plaintextSize = 512;
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encrypt(ags, plaintext, aad, firstSegmentOffset);

    // truncate the ciphertext
    for (int i = 0; i < ciphertext.length; i += 8) {
      byte[] truncatedCiphertext = Arrays.copyOf(ciphertext, i);
      tryDecryptModifiedCiphertext(
          ags, firstSegmentOffset, truncatedCiphertext, aad, 128, plaintext);
    }

    // Append stuff to ciphertext
    int[] sizes = new int[] {1, (segmentSize - ciphertext.length % segmentSize), segmentSize};
    for (int appendedBytes : sizes) {
      byte[] modifiedCiphertext = concatBytes(ciphertext, new byte[appendedBytes]);
      tryDecryptModifiedCiphertext(
          ags, firstSegmentOffset, modifiedCiphertext, aad, 128, plaintext);
    }

    // flip bits
    for (int pos = firstSegmentOffset; pos < ciphertext.length; pos++) {
      byte[] modifiedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);
      modifiedCiphertext[pos] ^= (byte) 1;
      tryDecryptModifiedCiphertext(
          ags, firstSegmentOffset, modifiedCiphertext, aad, 128, plaintext);
    }

    // delete segments
    for (int segment = 0; segment < (ciphertext.length / segmentSize); segment++) {
      byte[] modifiedCiphertext =
          concatBytes(
              Arrays.copyOf(ciphertext, segment * segmentSize),
              Arrays.copyOfRange(ciphertext, (segment + 1) * segmentSize, ciphertext.length));
      tryDecryptModifiedCiphertext(
          ags, firstSegmentOffset, modifiedCiphertext, aad, 128, plaintext);
    }

    // duplicate segments
    for (int segment = 0; segment < (ciphertext.length / segmentSize); segment++) {
      byte[] modifiedCiphertext =
          concatBytes(
              Arrays.copyOf(ciphertext, (segment + 1) * segmentSize),
              Arrays.copyOfRange(ciphertext, segment * segmentSize, ciphertext.length));
      tryDecryptModifiedCiphertext(
          ags, firstSegmentOffset, modifiedCiphertext, aad, 128, plaintext);
    }

    // Modify aad
    // When the additional data is modified then any attempt to read plaintext must fail.
    for (int pos = 0; pos < aad.length; pos++) {
      byte[] modifiedAad = Arrays.copyOf(aad, aad.length);
      modifiedAad[pos] ^= (byte) 1;
      tryDecryptModifiedCiphertext(
          ags, firstSegmentOffset, ciphertext, modifiedAad, 128, new byte[0]);
    }
  }

  /**
   * Tries to decrypt a modified ciphertext using an SeekableByteChannel. Each call to read must
   * either return the original plaintext (e.g. when the modification in the ciphertext does not
   * affect the plaintext) or it must throw an IOException.
   */
  private static void tryDecryptModifiedCiphertextWithSeekableByteChannel(
      StreamingAead ags, byte[] modifiedCiphertext, byte[] aad, byte[] plaintext) throws Exception {

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
          assertTrue(
              "start:" + start + " read:" + read + " length:" + length,
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

  public static void testModifiedCiphertextWithSeekableByteChannel(
      StreamingAead ags, int segmentSize, int firstSegmentOffset) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    int plaintextSize = 2000;
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encrypt(ags, plaintext, aad, firstSegmentOffset);

    // truncate the ciphertext
    for (int i = 0; i < ciphertext.length; i += 64) {
      byte[] truncatedCiphertext = Arrays.copyOf(ciphertext, i);
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, truncatedCiphertext, aad, plaintext);
    }

    // Append stuff to ciphertext
    int[] sizes = new int[] {1, (segmentSize - ciphertext.length % segmentSize), segmentSize};
    for (int appendedBytes : sizes) {
      byte[] modifiedCiphertext = concatBytes(ciphertext, new byte[appendedBytes]);
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, modifiedCiphertext, aad, plaintext);
    }

    // flip bits
    for (int pos = firstSegmentOffset; pos < ciphertext.length; pos++) {
      byte[] modifiedCiphertext = Arrays.copyOf(ciphertext, ciphertext.length);
      modifiedCiphertext[pos] ^= (byte) 1;
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, modifiedCiphertext, aad, plaintext);
    }

    // delete segments
    for (int segment = 0; segment < (ciphertext.length / segmentSize); segment++) {
      byte[] modifiedCiphertext =
          concatBytes(
              Arrays.copyOf(ciphertext, segment * segmentSize),
              Arrays.copyOfRange(ciphertext, (segment + 1) * segmentSize, ciphertext.length));
      tryDecryptModifiedCiphertextWithSeekableByteChannel(ags, modifiedCiphertext, aad, plaintext);
    }

    // duplicate segments
    for (int segment = 0; segment < (ciphertext.length / segmentSize); segment++) {
      byte[] modifiedCiphertext =
          concatBytes(
              Arrays.copyOf(ciphertext, (segment + 1) * segmentSize),
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
   * Reads everything from plaintext, encrypt it and writes the result to ciphertext. This method is
   * used to test aynchronous encryption.
   *
   * @param ags the streaming encryption
   * @param plaintext the channel containing the plaintext
   * @param ciphertext the channel to which the ciphertext is written
   * @param aad the additional data to authenticate
   * @param chunkSize the size of blocks that are read and written. This size determines the
   *     temporary memory used in this method but is independent of the streaming encryption.
   * @throws RuntimeException if something goes wrong.
   */
  private static void encryptChannel(
      StreamingAead ags,
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
   * Constructs a ReadableByteChannel with ciphertext from a ReadableByteChannel. The method
   * constructs a new thread that is used to encrypt the plaintext. TODO(bleichen): Using
   * PipedInputStream may have performance problems.
   */
  private static ReadableByteChannel ciphertextChannel(
      final StreamingAead ags,
      final ReadableByteChannel plaintext,
      final byte[] aad,
      final int chunkSize)
      throws Exception {
    PipedOutputStream output = new PipedOutputStream();
    PipedInputStream result = new PipedInputStream(output);
    final WritableByteChannel ciphertext = Channels.newChannel(output);
    new Thread(
            new Runnable() {
              @Override
              public void run() {
                encryptChannel(ags, plaintext, ciphertext, aad, chunkSize);
              }
            })
        .start();
    return Channels.newChannel(result);
  }

  /** Encrypt and decrypt a long ciphertext. */
  public static void testEncryptDecryptLong(StreamingAead ags, long plaintextSize)
      throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
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
        int unused = copy.read(expected);
        decryptedBytes += read;
        TestUtil.assertByteArrayEquals(expected.array(), Arrays.copyOf(chunk, read));
      }
    } while (read != -1);
    assertEquals(plaintextSize, decryptedBytes);
  }

  /** Encrypt some plaintext to a file, then decrypt from the file */
  public static void testFileEncryption(StreamingAead ags, File tmpFile) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    int plaintextSize = 1 << 18;
    ByteBufferChannel plaintext = new ByteBufferChannel(generatePlaintext(plaintextSize));

    // Encrypt to file
    WritableByteChannel bc =
        ags.newEncryptingChannel(new FileOutputStream(tmpFile).getChannel(), aad);
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
    ReadableByteChannel ptStream =
        ags.newDecryptingChannel(new FileInputStream(tmpFile).getChannel(), aad);
    int decryptedSize = 0;
    do {
      ByteBuffer decrypted = ByteBuffer.allocate(512);
      read = ptStream.read(decrypted);
      if (read > 0) {
        ByteBuffer expected = ByteBuffer.allocate(read);
        plaintext.read(expected);
        decrypted.flip();
        TestUtil.assertByteBufferContains(expected.array(), decrypted);
        decryptedSize += read;
      }
    } while (read != -1);
    assertEquals(plaintextSize, decryptedSize);

    // Decrypt file partially using FileChannel and compare to plaintext
    plaintext.rewind();
    SeekableByteChannel ptChannel =
        ags.newSeekableDecryptingChannel(new FileInputStream(tmpFile).getChannel(), aad);
    SecureRandom random = new SecureRandom();
    for (int samples = 0; samples < 100; samples++) {
      int start = random.nextInt(plaintextSize);
      int length = random.nextInt(plaintextSize / 100 + 1);
      ByteBuffer decrypted = ByteBuffer.allocate(length);
      ptChannel.position(start);
      read = ptChannel.read(decrypted);
      // We expect that all read of ctChannel return the requested number of bytes.
      // Hence we also expect that ptChannel returns the maximal number of bytes.
      if (read < length && read + start < plaintextSize) {
        fail(
            "Plaintext size is smaller than expected; read:"
                + read
                + " position:"
                + start
                + " length:"
                + length);
      }
      byte[] expected = new byte[read];
      plaintext.position(start);
      plaintext.read(ByteBuffer.wrap(expected));
      decrypted.flip();
      TestUtil.assertByteBufferContains(expected, decrypted);
    }
  }

  /** Encrypt some plaintext to a file using FileOutputStream, then decrypt from the file */
  public static void testFileEncrytionWithStream(StreamingAead ags, File tmpFile) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    int plaintextSize = 1 << 15;
    byte[] pt = generatePlaintext(plaintextSize);
    FileOutputStream ctStream = new FileOutputStream(tmpFile);
    WritableByteChannel channel = Channels.newChannel(ctStream);
    WritableByteChannel encChannel = ags.newEncryptingChannel(channel, aad);
    OutputStream encStream = Channels.newOutputStream(encChannel);

    // Writing single bytes appears to be the most troubling case.
    for (int i = 0; i < pt.length; i++) {
      encStream.write(pt[i]);
    }
    encStream.close();

    FileInputStream inpStream = new FileInputStream(tmpFile);
    ReadableByteChannel inpChannel = Channels.newChannel(inpStream);
    ReadableByteChannel decryptedChannel = ags.newDecryptingChannel(inpChannel, aad);
    InputStream decrypted = Channels.newInputStream(decryptedChannel);
    int decryptedSize = 0;
    int read;
    while (true) {
      read = decrypted.read();
      if (read == -1) {
        break;
      }
      if (read != (pt[decryptedSize] & 0xff)) {
        fail(
            "Incorrect decryption at position "
                + decryptedSize
                + " expected: "
                + pt[decryptedSize]
                + " read:"
                + read);
      }
      decryptedSize += 1;
    }
    assertEquals(plaintextSize, decryptedSize);
  }
}
