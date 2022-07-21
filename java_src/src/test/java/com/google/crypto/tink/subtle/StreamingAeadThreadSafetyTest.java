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
import static org.junit.Assert.fail;

import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.testing.StreamingTestUtil.ByteBufferChannel;
import com.google.crypto.tink.testing.StreamingTestUtil.SeekableByteBufferChannel;
import com.google.crypto.tink.testing.TestUtil;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Test for thread safety of {@code StreamingAead}-primitives.
 *
 * <p>Note: the {@code StreamingAead}-primitives tested here have not been designed to be used
 * concurrently. The main motivation for having atomic reads and writes is to ensure the integrity
 * of the operations. This simply helps to ensure that nonces and keystreams are used once.
 *
 * <p>If possible then this unit test should be run using a thread sanitizer. Otherwise only race
 * conditions that actually happend during the test will be detected.
 */
@RunWith(JUnit4.class)
public class StreamingAeadThreadSafetyTest {

  /**
   * Exception handler for uncaught exceptions in a thread.
   *
   * <p>TODO(bleichen): Surely there must be a better way to catch exceptions in threads in unit
   * tests. junit ought to do this. However, at least for some setups, tests can pass despite
   * uncaught exceptions in threads.
   */
  public static class ExceptionHandler implements Thread.UncaughtExceptionHandler {

    private Throwable firstException = null;

    @Override
    public void uncaughtException(Thread thread, Throwable ex) {
      if (firstException == null) {
        firstException = ex;
      }
    }

    public void check() throws Exception {
      if (firstException != null) {
        throw new Exception("Thread failed", firstException);
      }
    }
  }

  /**
   * Convenience method for encrypting some plaintext.
   *
   * @param stream the streaming primitive
   * @param plaintext the plaintext to encrypt
   * @param associatedData the additional data to authenticate
   * @return the ciphertext including a prefix of size ags.firstSegmentOffset
   */
  private byte[] encrypt(StreamingAead stream, byte[] plaintext, byte[] associatedData)
      throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    WritableByteChannel ctChannel = Channels.newChannel(bos);
    // ctChannel.write(ByteBuffer.allocate(stream.getFirstSegmentOffset()));
    WritableByteChannel encChannel = stream.newEncryptingChannel(ctChannel, associatedData);
    encChannel.write(ByteBuffer.wrap(plaintext));
    encChannel.close();
    byte[] ciphertext = bos.toByteArray();
    return ciphertext;
  }

  /** A thread that reads plaintext in multiple chunks from a channel. */
  public static class DecryptingThread extends Thread {
    private ReadableByteChannel channel;
    private ByteBuffer plaintext;
    private int chunkSize;

    /**
     * Constructs a thread that reads plaintext in multiple chunks from a channel.
     *
     * @param channel the channel to read the plaintext from. The channel should be in blocking
     *     mode.
     * @param plaintextSize the size of the plaintext to read.
     * @param chunkSize the size of the chunks that are read.
     */
    DecryptingThread(ReadableByteChannel channel, int plaintextSize, int chunkSize) {
      this.channel = channel;
      this.plaintext = ByteBuffer.allocate(plaintextSize);
      this.chunkSize = chunkSize;
    }

    /**
     * Read the plaintext from the channel. This implementation assumes that the channel is blocking
     * and throws an AssertionError if an attempt to read plaintext from the channel is incomplete.
     */
    @Override
    public void run() {
      try {
        byte[] chunk = new byte[chunkSize];
        while (plaintext.remaining() >= chunkSize) {
          int read = channel.read(ByteBuffer.wrap(chunk));
          assertEquals(read, chunkSize);
          plaintext.put(chunk);
        }
        channel.read(plaintext);
        assertEquals(0, plaintext.remaining());
      } catch (IOException ex) {
        getUncaughtExceptionHandler().uncaughtException(this, ex);
      }
    }
  }

  /**
   * Test for thread safety. This test is an incorrect use case for StreamingAead implementations.
   * Streams have state and hence their behaviour is not well defined. Nevertheless if an encrypting
   * channel is used concurrently we expect the following behaviour: (1) All bytes are read (2) The
   * thread sanitizer does not find anything.
   */
  public void testDecryption(StreamingAead stream, byte[] associatedData, int chunkSize)
      throws Exception {
    int numberOfThreads = 10;
    int plaintextSize = 5432; // The plaintext size for each thread.
    byte[] ciphertext = encrypt(stream, new byte[numberOfThreads * plaintextSize], associatedData);
    SeekableByteChannel ctChannel = new SeekableByteBufferChannel(ciphertext);
    SeekableByteChannel decChannel = stream.newSeekableDecryptingChannel(ctChannel, associatedData);

    ExceptionHandler exceptionHandler = new ExceptionHandler();
    Thread[] thread = new Thread[numberOfThreads];
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i] = new DecryptingThread(decChannel, plaintextSize, chunkSize);
      thread[i].setUncaughtExceptionHandler(exceptionHandler);
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].start();
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].join();
    }
    exceptionHandler.check();

    // Each thread has read plaintextSize bytes from decChannel. Hence nothing should be left.
    int read = decChannel.read(ByteBuffer.allocate(1));
    assertEquals(-1, read);
  }

  @Test
  public void testDecryptionAesGcm() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] associatedData = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 16;
    int segmentSize = 512;
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, "HmacSha256", keySize, segmentSize, 0);
    testDecryption(ags, associatedData, 64);
  }

  @Test
  public void testDecryptionAesCtrHmac() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] associatedData = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 512;
    AesCtrHmacStreaming stream = new AesCtrHmacStreaming(
        ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize, 0);
    testDecryption(stream, associatedData, 64);
  }

  /** A thread that writes a number of chunks consisting of the same plaintextByte to a channel. */
  public static class EncryptingThread extends Thread {
    private WritableByteChannel channel;
    private int chunkSize;
    private int numberOfChunks;
    private byte plaintextByte;

    /**
     * Construct a thread that writes a number of chunks consisting of the same plaintextByte to a
     * channel.
     *
     * @param channel the channel where the bytes are written to.
     * @param chunkSize the size of the chunks written
     * @param numberOfChunks the number of chunks written to the channel
     * @param plaintextByte the plaintextByte repeated in all the chunks.
     */
    EncryptingThread(
        WritableByteChannel channel, int chunkSize, int numberOfChunks, byte plaintextByte) {
      this.channel = channel;
      this.chunkSize = chunkSize;
      this.numberOfChunks = numberOfChunks;
      this.plaintextByte = plaintextByte;
    }

    /**
     * Write the plaintext to the channel. This implementation assumes that the channel is blocking
     * and throws an AssertionError if an attempt to write plaintext to the channel is incomplete.
     */
    @Override
    public void run() {
      try {
        byte[] chunk = new byte[chunkSize];
        for (int i = 0; i < chunkSize; i++) {
          chunk[i] = plaintextByte;
        }
        for (int i = 0; i < numberOfChunks; i++) {
          int written = channel.write(ByteBuffer.wrap(chunk));
          assertEquals(written, chunkSize);
        }
      } catch (IOException ex) {
        getUncaughtExceptionHandler().uncaughtException(this, ex);
      }
    }
  }

  /**
   * Test for thread safety. This test is an incorrect use case for StreamingAead implementations.
   * Streams have state and hence their behaviour is not well defined. Nevertheless if an encrypting
   * channel is used concurrently we expect the following behaviour: (1) The resulting ciphertext
   * has valid format. (2) All plaintext is encrypted. (3) The thread sanitizer does not find
   * anything.
   */
  public void testEncryption(
      StreamingAead stream, byte[] associatedData, int chunkSize, int numberOfChunks)
      throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    WritableByteChannel encChannel =
        stream.newEncryptingChannel(Channels.newChannel(bos), associatedData);
    int numberOfThreads = 10;
    Thread[] thread = new Thread[numberOfThreads];
    ExceptionHandler exceptionHandler = new ExceptionHandler();
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i] = new EncryptingThread(encChannel, chunkSize, numberOfChunks, (byte) i);
      thread[i].setUncaughtExceptionHandler(exceptionHandler);
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].start();
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].join();
    }
    exceptionHandler.check();
    encChannel.close();
    byte[] ciphertext = bos.toByteArray();
    ReadableByteChannel ctChannel = new ByteBufferChannel(ciphertext);
    ReadableByteChannel ptChannel = stream.newDecryptingChannel(ctChannel, associatedData);
    ByteBuffer decrypted = ByteBuffer.allocate(numberOfThreads * chunkSize * numberOfChunks + 1);
    ptChannel.read(decrypted);

    // Test whether the writing the chunks was done in an atomic manner.
    byte[] plaintext = decrypted.array();
    for (int i = 0; i < numberOfThreads * numberOfChunks; i++) {
      for (int j = 0; j < chunkSize - 1; j++) {
        int idx = i * chunkSize + j;
        if (plaintext[idx] != plaintext[idx + 1]) {
          int thread1 = plaintext[idx] & 0xff;
          int thread2 = plaintext[idx + 1] & 0xff;
          fail("Chunk " + i + " contains bytes from thread " + thread1 + " and " + thread2 + ".");
        }
      }
    }
  }

  @Test
  public void testEncryptionAesGcm() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] associatedData = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 16;
    int segmentSize = 512;
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, "HmacSha256", keySize, segmentSize, 0);
    testEncryption(ags, associatedData, 129, 20);
  }

  @Test
  public void testEncryptionAesCtrHmac() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] associatedData = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 512;
    AesCtrHmacStreaming stream = new AesCtrHmacStreaming(
        ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize, 0);
    testEncryption(stream, associatedData, 128, 20);
  }

  @Test
  public void testEncryptionLargeChunks() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] associatedData = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 16;
    int segmentSize = 512;
    int chunkSize = 2048; // the size for each concurrent read.
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, "HmacSha256", keySize, segmentSize, 0);
    testEncryption(ags, associatedData, chunkSize, 2);
  }

  @Test
  public void testEncryptionSmallChunks() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] associatedData = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 16;
    int segmentSize = 512;
    int chunkSize = 3; // the size for each concurrent read.
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, "HmacSha256", keySize, segmentSize, 0);
    testEncryption(ags, associatedData, chunkSize, 1000);
  }

  /**
   * A thread that randomly reads plaintext from a channel.
   */
  public static class RandomAccessThread extends Thread {
    private SeekableByteChannel channel;
    private int numberOfReads;
    private int plaintextSize;

    /**
     * Constructs a thread that randomly reads plaintext from a channel.
     *
     * @param channel the channel to read the plaintext from. The channel should be in blocking
     *     mode. The i-th byte of the plaintext is (byte) i.
     * @param plaintextSize the size of the plaintext to read.
     * @param numberOfReads the number of random access reads.
     */
    RandomAccessThread(SeekableByteChannel channel, int plaintextSize, int numberOfReads) {
      this.channel = channel;
      this.numberOfReads = numberOfReads;
      this.plaintextSize = plaintextSize;
    }

    /**
     * Read the plaintext from the channel. This implementation assumes that the channel is blocking
     * and throws an AssertionError if an attempt to read plaintext from the channel is incomplete.
     */
    @Override
    public void run() {
      SecureRandom rand = new SecureRandom();
      for (int j = 0; j < numberOfReads; j++) {
        int pos = rand.nextInt(plaintextSize);
        int size = rand.nextInt(plaintextSize / 10) + 1;
        ByteBuffer plaintext = ByteBuffer.allocate(size);
        try {
          channel.position(pos);
          int read = channel.read(plaintext);
          if (read == -1) {
            continue;
          }
        } catch (IOException ex) {
          getUncaughtExceptionHandler().uncaughtException(this, ex);
        }
        // We expect that both channel.position(pos) and
        // channel.read() are atomic, but we cannot assume that read actually reads the
        // plaintext at position pos. The only assumption that can be made is that the plaintext
        // is a continuous part of the plaintext.
        for (int i = 1; i < plaintext.position(); i++) {
          if (((plaintext.get(i - 1) + 1) & 0xff) != (plaintext.get(i) & 0xff)) {
            fail(
                "Plaintext is not continuous at position:"
                    + (pos + i)
                    + " size:"
                    + plaintext.position()
                    + " start:"
                    + pos
                    + "\nbytes:"
                    + TestUtil.hexEncode(plaintext.array()));
          }
        }
      }
    }
  }

  /**
   * Test for thread safety using SeekableByteChannels. This test is an incorrect use case for
   * StreamingAead implementations, since SeekableByteChannels can't be used in multiple threads.
   * I.e. an implementation cannot guarantee that no other thread modifies the stream between a call
   * to SeekableByteChannel.position(long) and SeekableByteChannel.read(ByteBuffer). Therefore, the
   * test here only checks whether the operations are atomic. E.g. a read should read contiuous
   * bytes.
   */
  public void testRandomAccessDecryption(
      StreamingAead stream, byte[] associatedData, int plaintextSize) throws Exception {
    int numberOfReads = 128;
    int numberOfThreads = 10;
    byte[] plaintext = new byte[plaintextSize];
    for (int i = 0; i < plaintextSize; i++) {
      // Setting plaintex[i] to (byte) i, allows the decrypting thread to check that the
      // plaintext is from a continuous part of the plaintext.
      plaintext[i] = (byte) i;
    }
    byte[] ciphertext = encrypt(stream, plaintext, associatedData);
    SeekableByteChannel ctChannel = new SeekableByteBufferChannel(ciphertext);
    SeekableByteChannel decChannel = stream.newSeekableDecryptingChannel(ctChannel, associatedData);

    ExceptionHandler exceptionHandler = new ExceptionHandler();
    Thread[] thread = new Thread[numberOfThreads];
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i] = new RandomAccessThread(decChannel, plaintextSize, numberOfReads);
      thread[i].setUncaughtExceptionHandler(exceptionHandler);
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].start();
    }
    for (int i = 0; i < numberOfThreads; i++) {
      thread[i].join();
    }
    exceptionHandler.check();
  }

  @Test
  public void testRandomAccessAesGcm() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] associatedData = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 16;
    int segmentSize = 503;
    int plaintextSize = 7654;
    AesGcmHkdfStreaming ags = new AesGcmHkdfStreaming(ikm, "HmacSha256", keySize, segmentSize, 0);
    testRandomAccessDecryption(ags, associatedData, plaintextSize);
  }

  @Test
  public void testRandomAccessAesCtrHmac() throws Exception {
    byte[] ikm = TestUtil.hexDecode("000102030405060708090a0b0c0d0e0f");
    byte[] associatedData = TestUtil.hexDecode("aabbccddeeff");
    int keySize = 16;
    int tagSize = 12;
    int segmentSize = 479;
    int plaintextSize = 7654;
    AesCtrHmacStreaming stream = new AesCtrHmacStreaming(
        ikm, "HmacSha256", keySize, "HmacSha256", tagSize, segmentSize, 0);
    testDecryption(stream, associatedData, plaintextSize);
  }
}
