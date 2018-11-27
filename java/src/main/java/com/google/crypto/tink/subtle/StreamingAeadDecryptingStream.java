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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * An instance of a InputStream that returns the plaintext for some ciphertext.
 *
 * <p>TODO(bleichen): define what the state is after an IOException.
 */
class StreamingAeadDecryptingStream extends FilterInputStream {
  // Each plaintext segment has 16 bytes more of memory than the actual plaintext that it contains.
  // This is a workaround for an incompatibility between Conscrypt and OpenJDK in their
  // AES-GCM implementations, see b/67416642, b/31574439, and cr/170969008 for more information.
  // Conscrypt refused to fix this issue, but even if they fixed it, there are always Android phones
  // running old versions of Conscrypt, so we decided to take matters into our own hands.
  // Why 16? Actually any number larger than 16 should work. 16 is the lower bound because it's the
  // size of the tags of each AES-GCM ciphertext segment.
  private static final int PLAINTEXT_SEGMENT_EXTRA_SIZE = 16;

  /**
   * A buffer containing ciphertext that has not yet been decrypted. The limit of ciphertextSegment
   * is set such that it can contain segment plus the first character of the next segment. It is
   * necessary to read a segment plus one more byte to decrypt a segment, since the last segment of
   * a ciphertext is encrypted differently.
   */
  private ByteBuffer ciphertextSegment;

  /**
   * A buffer containing a plaintext segment. The bytes in the range plaintexSegment.position() ..
   * plaintextSegment.limit() - 1 are plaintext that have been decrypted but not yet read out of
   * AesGcmInputStream.
   */
  private ByteBuffer plaintextSegment;

  /* Header information */
  private int headerLength;
  private boolean headerRead;

  /* Indicates whether the end of this InputStream has been reached. */
  private boolean endOfCiphertext;

  /* Indicates whether the end of the plaintext has been reached. */
  private boolean endOfPlaintext;

  /**
   * Indicates whether this stream is in a defined state. Currently the state of this instance
   * becomes undefined when an authentication error has occurred.
   */
  private boolean definedState;

  /** The additional data that is authenticated with the ciphertext. */
  private byte[] aad;

  /** The number of the current segment of ciphertext buffered in ciphertexSegment. */
  private int segmentNr;

  private final StreamSegmentDecrypter decrypter;
  private final int ciphertextSegmentSize;
  private final int firstCiphertextSegmentSize;

  public StreamingAeadDecryptingStream(
      NonceBasedStreamingAead streamAead, InputStream ciphertextStream, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    super(ciphertextStream);
    decrypter = streamAead.newStreamSegmentDecrypter();
    headerLength = streamAead.getHeaderLength();
    headerRead = false;
    aad = Arrays.copyOf(associatedData, associatedData.length);
    // ciphertextSegment is one byte longer than a ciphertext segment,
    // so that the code can decide if the current segment is the last segment in the
    // stream.
    ciphertextSegmentSize = streamAead.getCiphertextSegmentSize();
    ciphertextSegment = ByteBuffer.allocate(ciphertextSegmentSize + 1);
    ciphertextSegment.limit(0);
    firstCiphertextSegmentSize = ciphertextSegmentSize - streamAead.getCiphertextOffset();
    plaintextSegment = ByteBuffer.allocate(streamAead.getPlaintextSegmentSize()
        + PLAINTEXT_SEGMENT_EXTRA_SIZE);
    plaintextSegment.limit(0);
    headerRead = false;
    endOfCiphertext = false;
    endOfPlaintext = false;
    segmentNr = 0;
    definedState = true;
  }

  /**
   * Tries to read the header of the ciphertext.
   *
   * @return true if the header has been fully read and false if not enogh bytes were available from
   *     the ciphertext stream.
   * @throws IOException when an exception occurs while reading from @code{in} or when the header is
   *     too short.
   */
  private void readHeader() throws IOException {
    assert headerRead == false;
    byte[] header = new byte[headerLength];
    int bytesRead = in.read(header);
    if (bytesRead != headerLength) {
      setUndefinedState();
      throw new IOException("Ciphertext is too short");
    }
    try {
      decrypter.init(ByteBuffer.wrap(header), aad);
    } catch (GeneralSecurityException ex) {
      throw new IOException(ex);
    }
    headerRead = true;
  }

  private void setUndefinedState() {
    definedState = false;
    plaintextSegment.limit(0);
  }

  /** Loads the next plaintext segment. */
  private void loadSegment() throws IOException {
    // Try filling the ciphertextSegment
    while (!endOfCiphertext && ciphertextSegment.remaining() > 0) {
      int read =
          in.read(
              ciphertextSegment.array(),
              ciphertextSegment.position(),
              ciphertextSegment.remaining());
      if (read > 0) {
        ciphertextSegment.position(ciphertextSegment.position() + read);
      } else if (read == -1) {
        endOfCiphertext = true;
      } else if (read == 0) {
        // We expect that read returns at least one byte.
        throw new IOException("Could not read bytes from the ciphertext stream");
      }
    }
    byte lastByte = 0;
    if (!endOfCiphertext) {
      lastByte = ciphertextSegment.get(ciphertextSegment.position() - 1);
      ciphertextSegment.position(ciphertextSegment.position() - 1);
    }
    ciphertextSegment.flip();
    plaintextSegment.clear();
    try {
      decrypter.decryptSegment(ciphertextSegment, segmentNr, endOfCiphertext, plaintextSegment);
    } catch (GeneralSecurityException ex) {
      // The current segment did not validate.
      // Currently this means that decryption cannot resume.
      setUndefinedState();
      throw new IOException(
          ex.getMessage()
              + "\n"
              + toString()
              + "\nsegmentNr:"
              + segmentNr
              + " endOfCiphertext:"
              + endOfCiphertext,
          ex);
    }
    segmentNr += 1;
    plaintextSegment.flip();
    ciphertextSegment.clear();
    if (!endOfCiphertext) {
      ciphertextSegment.clear();
      ciphertextSegment.limit(ciphertextSegmentSize + 1);
      ciphertextSegment.put(lastByte);
    }
  }

  @Override
  public int read() throws IOException {
    byte[] oneByte = new byte[1];
    int ret = read(oneByte, 0, 1);
    if (ret == 1) {
      return oneByte[0] & 0xff;
    } else if (ret == -1) {
      return ret;
    } else {
      throw new IOException("Reading failed");
    }
  }

  @Override
  public int read(byte[] dst) throws IOException {
    return read(dst, 0, dst.length);
  }

  @Override
  public synchronized int read(byte[] dst, int offset, int length) throws IOException {
    if (!definedState) {
      throw new IOException("This StreamingAeadDecryptingStream is in an undefined state");
    }
    if (!headerRead) {
      readHeader();
      ciphertextSegment.clear();
      ciphertextSegment.limit(firstCiphertextSegmentSize + 1);
    }
    if (endOfPlaintext) {
      return -1;
    }
    int bytesRead = 0;
    while (bytesRead < length) {
      if (plaintextSegment.remaining() == 0) {
        if (endOfCiphertext) {
          endOfPlaintext = true;
          break;
        }
        loadSegment();
      }
      int sliceSize = java.lang.Math.min(plaintextSegment.remaining(), length - bytesRead);
      plaintextSegment.get(dst, bytesRead + offset, sliceSize);
      bytesRead += sliceSize;
    }
    if (bytesRead == 0 && endOfPlaintext) {
      return -1;
    } else {
      return bytesRead;
    }
  }

  @Override
  public synchronized void close() throws IOException {
    super.close();
  }

  @Override
  public synchronized int available() {
    return plaintextSegment.remaining();
  }

  @Override
  public synchronized void mark(int readlimit) {
    // Mark is not supported.
  }

  @Override
  public boolean markSupported() {
    return false;
  }

  /**
   * Skips over and discards <code>n</code> bytes of plaintext from the input stream. The
   * implementation reads and decrypts the plaintext that is skipped. Hence skipping a large number
   * of bytes is slow.
   *
   * <p>Returns the number of bytes skipped. This number can be smaller than the number of bytes
   * requested. This can happend for a number of reasons: e.g., this happens when the underlying
   * stream is non-blocking and not enough bytes are available or when the stream reaches the end of
   * the stream.
   *
   * @throws IOException when an exception occurs while reading from @code{in} or when the
   *     ciphertext is corrupt. Currently all corrupt ciphertext will be detected. However this
   *     behaviour may change.
   */
  @Override
  public long skip(long n) throws IOException {
    long maxSkipBufferSize = ciphertextSegmentSize;
    long remaining = n;
    if (n <= 0) {
      return 0;
    }
    int size = (int) Math.min(maxSkipBufferSize, remaining);
    byte[] skipBuffer = new byte[size];
    while (remaining > 0) {
      int bytesRead = read(skipBuffer, 0, (int) Math.min(size, remaining));
      if (bytesRead <= 0) {
        break;
      }
      remaining -= bytesRead;
    }
    return n - remaining;
  }

  /* Returns the state of the channel. */
  @Override
  public synchronized String toString() {
    StringBuilder res = new StringBuilder();
    res.append("StreamingAeadDecryptingStream")
        .append("\nsegmentNr:")
        .append(segmentNr)
        .append("\nciphertextSegmentSize:")
        .append(ciphertextSegmentSize)
        .append("\nheaderRead:")
        .append(headerRead)
        .append("\nendOfCiphertext:")
        .append(endOfCiphertext)
        .append("\nendOfPlaintext:")
        .append(endOfPlaintext)
        .append("\ndefinedState:")
        .append(definedState)
        .append("\nciphertextSgement")
        .append(" position:")
        .append(ciphertextSegment.position())
        .append(" limit:")
        .append(ciphertextSegment.limit())
        .append("\nplaintextSegment")
        .append(" position:")
        .append(plaintextSegment.position())
        .append(" limit:")
        .append(plaintextSegment.limit());
    return res.toString();
  }
}
