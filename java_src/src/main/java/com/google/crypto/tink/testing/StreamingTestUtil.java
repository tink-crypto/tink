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

package com.google.crypto.tink.testing;

import static java.lang.Math.min;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.subtle.Random;
import java.io.ByteArrayInputStream;
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
public final class StreamingTestUtil {
  /**
   * Implements a SeekableByteChannel for testing.
   *
   * <p>The implementation is backed by a ByteBuffer.
   */
  public static class SeekableByteBufferChannel extends ByteBufferChannel
      implements SeekableByteChannel {
    public SeekableByteBufferChannel(ByteBuffer buffer) {
      super(buffer);
    }

    public SeekableByteBufferChannel(ByteBuffer buffer, int maxChunkSize) {
      super(buffer, maxChunkSize);
    }

    public SeekableByteBufferChannel(byte[] bytes) {
      super(bytes);
    }

    public SeekableByteBufferChannel(byte[] bytes, int maxChunkSize) {
      super(bytes, maxChunkSize);
    }

    @Override
    public long position() throws ClosedChannelException {
      checkIsOpen();
      return buffer.position();
    }

    @Override
    public synchronized SeekableByteBufferChannel position(long newPosition)
        throws ClosedChannelException {
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
    public SeekableByteChannel truncate(long size) {
      throw new NonWritableChannelException();
    }
  }

  /**
   * Implements a ReadableByteChannel for testing.
   *
   * <p>The implementation is backed by a ByteBuffer.
   */
  public static class ByteBufferChannel implements ReadableByteChannel {
    final ByteBuffer buffer;
    private final boolean noDataEveryOtherRead;
    private boolean returnDataOnNextRead;

    /**
     * Defines the maximal size of a chunk that is transferred with a single write. This can be used
     * to test the behavior of streaming encryption with channels where not always sufficiently many
     * bytes are available during reads and writes.
     */
    final int maxChunkSize;

    /** keeps track whether the channel is still open. */
    private boolean isopen;

    public ByteBufferChannel(ByteBuffer buffer) {
      this(buffer, java.lang.Integer.MAX_VALUE);
    }

    public ByteBufferChannel(ByteBuffer buffer, int maxChunkSize) {
      this(buffer, maxChunkSize, /* noDataEveryOtherRead= */ false);
    }

    public ByteBufferChannel(ByteBuffer buffer, int maxChunkSize, boolean noDataEveryOtherRead) {
      this.buffer = buffer.duplicate();
      this.maxChunkSize = maxChunkSize;
      isopen = true;
      this.noDataEveryOtherRead = noDataEveryOtherRead;
      // when noDataEveryOtherRead, then the first read should already not return any data.
      this.returnDataOnNextRead = !noDataEveryOtherRead;
    }

    public ByteBufferChannel(byte[] bytes) {
      this(ByteBuffer.wrap(bytes));
    }

    public ByteBufferChannel(byte[] bytes, int maxChunkSize) {
      this(ByteBuffer.wrap(bytes), maxChunkSize);
    }

    public ByteBufferChannel(byte[] bytes, int maxChunkSize, boolean noDataEveryOtherRead) {
      this(ByteBuffer.wrap(bytes), maxChunkSize, noDataEveryOtherRead);
    }

    void checkIsOpen() throws ClosedChannelException {
      if (!isopen) {
        throw new ClosedChannelException();
      }
    }

    @Override
    public synchronized int read(ByteBuffer dst) throws IOException {
      checkIsOpen();
      if (this.noDataEveryOtherRead) {
        boolean returnData = this.returnDataOnNextRead;
        this.returnDataOnNextRead = !this.returnDataOnNextRead;
        if (!returnData) {
          return 0;
        }
      }
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

  /**
   * Implements a ByteArrayInputStream that returns only small chunks for testing.
   */
  public static class SmallChunksByteArrayInputStream extends ByteArrayInputStream {
    final int maxChunkSize;

    SmallChunksByteArrayInputStream(byte[] data, int maxChunkSize) {
      super(data);
      this.maxChunkSize = maxChunkSize;
    }

    @Override
    public synchronized int available() {
      return min(maxChunkSize, super.available());
    }

    @Override
    public synchronized int read(byte[] b) {
      return super.read(b, 0, min(b.length, maxChunkSize));
    }

    @Override
    public synchronized int read(byte[] b, int off, int len){
      return super.read(b, off, min(len, maxChunkSize));
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

    // Even longer plaintext. A typical cache size for data types such as BufferedInputStream
    // is 8 kB. Hence, testing with inputs longer than this makes sense.
    byte[] evenLongerPlaintext = Random.randBytes(16000);
    testEncryptionAndDecryption(
        encryptionStreamingAead, decryptionStreamingAead, evenLongerPlaintext, aad);

    // Empty plaintext.
    byte[] empty = new byte[0];
    testEncryptionAndDecryption(
        encryptionStreamingAead, decryptionStreamingAead, empty, aad);

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

    // Decrypt ciphertext via ReadableByteChannel, using a very small chunck size.
    {
      ByteBufferChannel ciphertextChannel = new ByteBufferChannel(
          ciphertext.toByteArray(), /* */10, true);
      ReadableByteChannel decChannel =
          decryptionStreamingAead.newDecryptingChannel(ciphertextChannel, aad);
      ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length);
      do {
        int unused = decChannel.read(decrypted);
      } while (decrypted.hasRemaining());
      // Compare results;
      TestUtil.assertByteArrayEquals(plaintext, decrypted.array());
    }

    // Decrypt ciphertext via SeekableByteChannel.
    {
      SeekableByteChannel ciphertextChannel =
          new SeekableByteBufferChannel(ciphertext.toByteArray());
      SeekableByteChannel decChannel =
          decryptionStreamingAead.newSeekableDecryptingChannel(ciphertextChannel, aad);
      ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length);
      int unused = decChannel.read(decrypted);

      // Compare results;
      TestUtil.assertByteArrayEquals(plaintext, decrypted.array());
    }

    // Decrypt ciphertext via SeekableByteChannel, using a very small chunck size.
    {
      SeekableByteChannel ciphertextChannel =
          new SeekableByteBufferChannel(ciphertext.toByteArray(), 10);
      SeekableByteChannel decChannel =
          decryptionStreamingAead.newSeekableDecryptingChannel(ciphertextChannel, aad);
      ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length);
      do {
        int unused = decChannel.read(decrypted);
      } while (decrypted.hasRemaining());
      // Compare results;
      TestUtil.assertByteArrayEquals(plaintext, decrypted.array());
    }

    // Decrypt ciphertext via SeekableByteChannel, setting position
    if (plaintext.length > 5) {
      SeekableByteChannel ciphertextChannel =
          new SeekableByteBufferChannel(ciphertext.toByteArray(), 10);
      SeekableByteChannel decChannel =
          decryptionStreamingAead.newSeekableDecryptingChannel(ciphertextChannel, aad);
      decChannel.position(5);
      assertEquals(5, decChannel.position());

      ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length - 5);
      do {
        int unused = decChannel.read(decrypted);
      } while (decrypted.hasRemaining());
      // Compare results;
      TestUtil.assertByteArrayEquals(
          Arrays.copyOfRange(plaintext, 5, plaintext.length),
          decrypted.array());
    }

    // Decrypt ciphertext via InputStream.
    {
      InputStream ctStream = new ByteArrayInputStream(ciphertext.toByteArray());
      InputStream decStream = decryptionStreamingAead.newDecryptingStream(ctStream, aad);
      byte[] decrypted = new byte[plaintext.length];
      int decryptedLength = decStream.read(decrypted);

      // Compare results;
      assertEquals("Decrypted length should be equal to plaintext length", decryptedLength,
          plaintext.length);
      TestUtil.assertByteArrayEquals(plaintext, decrypted);
    }

    // Decrypt ciphertext via SmallChunksByteArrayInputStream.
    {
      InputStream ctStream = new SmallChunksByteArrayInputStream(ciphertext.toByteArray(), 10);
      InputStream decStream = decryptionStreamingAead.newDecryptingStream(ctStream, aad);
      byte[] decrypted = new byte[plaintext.length];
      int decryptedLength = decStream.read(decrypted);

      // Compare results;
      assertEquals("Decrypted length should be equal to plaintext length", decryptedLength,
          plaintext.length);
      TestUtil.assertByteArrayEquals(plaintext, decrypted);
    }

    // Encrypt with an OutputStream.
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    OutputStream encStream = encryptionStreamingAead.newEncryptingStream(bos, aad);
    encStream.write(plaintext);
    encStream.close();
    byte[] ciphertext2 = bos.toByteArray();

    // Check that the stream encrypted ciphertext is correct.
    {
      ByteBufferChannel ciphertextChannel = new ByteBufferChannel(ciphertext2);
      ReadableByteChannel decChannel =
          decryptionStreamingAead.newDecryptingChannel(ciphertextChannel, aad);
      ByteBuffer decrypted = ByteBuffer.allocate(plaintext.length);
      int unused = decChannel.read(decrypted);

      // Compare results;
      TestUtil.assertByteArrayEquals(plaintext, decrypted.array());
    }

  }

  // Methods for testEncryptDecrypt.

  /**
   * Convenience method for encrypting some plaintext.
   *
   * @param ags the streaming primitive
   * @param plaintext the plaintext to encrypt
   * @param aad the additional data to authenticate
   * @param firstSegmentOffset the offset of the first ciphertext segment
   * @return the ciphertext including a prefix of size ags.firstSegmentOffset
   */
  public static byte[] encryptWithChannel(
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

  // Methods for testEncryptDecryptLong.

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
  private static void encryptWithChannel(
      StreamingAead ags,
      ReadableByteChannel plaintext,
      WritableByteChannel ciphertext,
      byte[] aad,
      int chunkSize) {
    try (WritableByteChannel encChannel = ags.newEncryptingChannel(ciphertext, aad)) {
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
    } catch (Exception ex) {
      // TODO(bleichen): What is the best way to chatch exceptions in threads?
      throw new RuntimeException(ex);
    }
  }

  private static byte[] encryptWithStream(StreamingAead ags, byte[] plaintext, byte[] aad,
      int firstSegmentOffset) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(new byte[firstSegmentOffset]);
    OutputStream encChannel = ags.newEncryptingStream(bos, aad);
    encChannel.write(plaintext);
    encChannel.close();
    byte[] ciphertext = bos.toByteArray();
    return ciphertext;
  }

  /**
   * Encrypts and decrypts some plaintext in a stream and checks that the expected plaintext is
   * returned.
   */
  private static void testEncryptDecryptWithChannel(
      StreamingAead ags, int firstSegmentOffset, int plaintextSize, int chunkSize)
      throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encryptWithChannel(ags, plaintext, aad, firstSegmentOffset);

    // Construct an InputStream from the ciphertext where the first
    // firstSegmentOffset bytes have already been read.
    ReadableByteChannel ctChannel =
        new SeekableByteBufferChannel(ciphertext).position(firstSegmentOffset);

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

  /**
   * Encrypts and decrypts some plaintext in a stream and checks that the expected plaintext is
   * returned.
   *
   * @param ags the StreamingAead test object.
   * @param firstSegmentOffset number of bytes prepended to the ciphertext stream.
   * @param plaintextSize the size of the plaintext
   * @param chunkSize decryption read chunks of this size.
   */
  private static void testEncryptDecryptWithStream(
      StreamingAead ags, int firstSegmentOffset, int plaintextSize, int chunkSize)
      throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encryptWithStream(ags, plaintext, aad, firstSegmentOffset);

    // Construct an InputStream from the ciphertext where the first
    // firstSegmentOffset bytes have already been read.
    InputStream ctStream = new ByteArrayInputStream(ciphertext);
    ctStream.read(new byte[firstSegmentOffset]);

    // Construct an InputStream that returns the plaintext.
    InputStream ptStream = ags.newDecryptingStream(ctStream, aad);
    int decryptedSize = 0;
    while (true) {
      byte[] chunk = new byte[chunkSize];
      int read = ptStream.read(chunk);
      if (read == -1) {
        break;
      }
      byte[] expected = Arrays.copyOfRange(plaintext, decryptedSize, decryptedSize + read);
      TestUtil.assertByteArrayEquals(expected, Arrays.copyOf(chunk, read));
      decryptedSize += read;
      if (read < chunkSize && decryptedSize < plaintextSize) {
        // read should block until either all requested bytes are read, the end of the stream has
        // been reached or an error occurred.
        fail("read did not return enough bytes");
      }
    }
    assertEquals("Size of decryption does not match plaintext", plaintextSize, decryptedSize);
  }

  public static void testEncryptDecrypt(
       StreamingAead ags, int firstSegmentOffset, int plaintextSize, int chunkSize)
      throws Exception {
    testEncryptDecryptWithChannel(ags, firstSegmentOffset, plaintextSize, chunkSize);
    testEncryptDecryptWithStream(ags, firstSegmentOffset, plaintextSize, chunkSize);
  }

  // Methods for testEncryptDecryptRandomAccess.

  /** Encrypt and then decrypt partially, and check that the result is the same. */
  public static void testEncryptDecryptRandomAccess(
      StreamingAead ags, int firstSegmentOffset, int plaintextSize) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encryptWithChannel(ags, plaintext, aad, firstSegmentOffset);

    // Construct a channel with random access for the ciphertext.
    SeekableByteChannel bbc = new SeekableByteBufferChannel(ciphertext);
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

  /**
   * Encrypts and decrypts some plaintext in a stream using skips and checks that the expected
   * plaintext is returned for the parts not skipped.
   *
   * @param ags the StreamingAead test object.
   * @param firstSegmentOffset number of bytes prepended to the ciphertext stream.
   * @param plaintextSize the size of the plaintext
   * @param chunkSize decryption skips and reads chunks of this size.
   */
  public static void testSkipWithStream(
      StreamingAead ags, int firstSegmentOffset, int plaintextSize, int chunkSize)
      throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    byte[] plaintext = generatePlaintext(plaintextSize);
    byte[] ciphertext = encryptWithStream(ags, plaintext, aad, firstSegmentOffset);

    // Runs this part twice skips the chunk number i if skipChunk == i % 2.
    for (int skipChunk = 0; skipChunk < 2; skipChunk++) {
      // Construct an InputStream from the ciphertext where the first
      // firstSegmentOffset bytes have already been read.
      InputStream ctStream = new ByteArrayInputStream(ciphertext);
      ctStream.read(new byte[firstSegmentOffset]);

      // Construct an InputStream that returns the plaintext.
      InputStream ptStream = ags.newDecryptingStream(ctStream, aad);
      int decryptedSize = 0;
      int chunkNumber = 0;
      while (true) {
        if (chunkNumber % 2 == skipChunk) {
          int bytesSkipped = (int) ptStream.skip(chunkSize);
          if (bytesSkipped < 0) {
            fail("skip must not return a negative integer (not even at eof).");
          }
          if (bytesSkipped == 0) {
            // The implementation here is blocking. Hence getting 0 here implies that
            // the end of the stream has been reached. However, this has not been
            // verified yet.
            assertEquals("Expecting end of stream after a 0-byte skip.", -1, ptStream.read());
            break;
          }
          decryptedSize += bytesSkipped;
          if (decryptedSize < plaintextSize) {
            // The stream is blocking. Hence we expect the number of requested
            // bytes unless the end of the stream has been reached.
            assertEquals("Size of skipped chunk is invalid", chunkSize, bytesSkipped);
          }
        } else {
          byte[] chunk = new byte[chunkSize];
          int read = ptStream.read(chunk);
          if (read == -1) {
            break;
          }
          byte[] expected = Arrays.copyOfRange(plaintext, decryptedSize, decryptedSize + read);
          TestUtil.assertByteArrayEquals(expected, Arrays.copyOf(chunk, read));
          decryptedSize += read;
          if (read < chunkSize && decryptedSize < plaintextSize) {
            // read should block until either all requested bytes are read, the end of the stream
            // has been reached or an error occurred.
            fail("read did not return enough bytes");
          }
        }
        chunkNumber += 1;
      }
      assertEquals("Size of decryption does not match plaintext", plaintextSize, decryptedSize);
    }

    // Checks whether skipping at the end of a broken ciphertext is detected.
    InputStream brokenCtStream = new ByteArrayInputStream(ciphertext, 0, ciphertext.length - 1);
    brokenCtStream.read(new byte[firstSegmentOffset]);
    InputStream brokenPtStream = ags.newDecryptingStream(brokenCtStream, aad);
    try {
      brokenPtStream.skip(2 * plaintextSize);
      brokenPtStream.read();
      fail("Failed to detect invalid ciphertext");
    } catch (IOException ex) {
      // expected
    }
  }

  // Methods for testEncryptSingleBytes.

  private static void testEncryptSingleBytesWithChannel(StreamingAead ags, int plaintextSize)
      throws Exception {
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

  private static void testEncryptSingleBytesWithStream(StreamingAead ags, int plaintextSize)
      throws Exception {
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

  public static void testEncryptSingleBytes(StreamingAead ags, int plaintextSize) throws Exception {
    testEncryptSingleBytesWithChannel(ags, plaintextSize);
    testEncryptSingleBytesWithStream(ags, plaintextSize);
  }

  // Methods for testEncryptDecryptString.

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
    SeekableByteChannel ctBuffer = new SeekableByteBufferChannel(ByteBuffer.wrap(ciphertext));
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

  // Methods for testModifiedCiphertext.

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
    SeekableByteChannel ct = new SeekableByteBufferChannel(modifiedCiphertext);
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
    byte[] ciphertext = encryptWithChannel(ags, plaintext, aad, firstSegmentOffset);

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

  // Methods for testModifiedCiphertextWithSeekableByteChannel.

  /**
   * Tries to decrypt a modified ciphertext using an SeekableByteChannel. Each call to read must
   * either return the original plaintext (e.g. when the modification in the ciphertext does not
   * affect the plaintext) or it must throw an IOException.
   */
  private static void tryDecryptModifiedCiphertextWithSeekableByteChannel(
      StreamingAead ags, byte[] modifiedCiphertext, byte[] aad, byte[] plaintext) throws Exception {

    SeekableByteChannel bbc = new SeekableByteBufferChannel(modifiedCiphertext);
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
    byte[] ciphertext = encryptWithChannel(ags, plaintext, aad, firstSegmentOffset);

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
   * Constructs a ReadableByteChannel with ciphertext from a ReadableByteChannel. The method
   * constructs a new thread that is used to encrypt the plaintext. TODO(bleichen): Using
   * PipedInputStream may have performance problems.
   */
  private static ReadableByteChannel createCiphertextChannel(
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
                encryptWithChannel(ags, plaintext, ciphertext, aad, chunkSize);
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
    ReadableByteChannel ciphertext = createCiphertextChannel(ags, plaintext, aad, 1 << 20);
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

  // Methods for testFileEncryption.

  /** Encrypt some plaintext to a file, then decrypt from the file */
  private static void testFileEncryptionWithChannel(
      StreamingAead ags, File tmpFile, int plaintextSize) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
    SeekableByteBufferChannel plaintext =
        new SeekableByteBufferChannel(generatePlaintext(plaintextSize));

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

  /**
   * Encrypts some plaintext to a file using FileOutputStream, then decrypt with a FileInputStream.
   * Reading and writing is done byte by byte.
   */
  private static void testFileEncryptionWithStream(
      StreamingAead ags, File tmpFile, int plaintextSize) throws Exception {
    byte[] aad = TestUtil.hexDecode("aabbccddeeff");
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

  public static void testFileEncryption(StreamingAead ags, File tmpFile, int plaintextSize)
      throws Exception {
    testFileEncryptionWithChannel(ags, tmpFile, plaintextSize);
    testFileEncryptionWithStream(ags, tmpFile, plaintextSize);
  }

  private StreamingTestUtil() {}
}
