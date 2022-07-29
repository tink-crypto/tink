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

import androidx.annotation.RequiresApi;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * An instance of {@link SeekableByteChannel} that allows random access to the plaintext of some
 * ciphertext.
 */
@RequiresApi(24) // https://developer.android.com/reference/java/nio/channels/SeekableByteChannel
class StreamingAeadSeekableDecryptingChannel implements SeekableByteChannel {
  // Each plaintext segment has 16 bytes more of memory than the actual plaintext that it contains.
  // This is a workaround for an incompatibility between Conscrypt and OpenJDK in their
  // AES-GCM implementations, see b/67416642, b/31574439, and cr/170969008 for more information.
  // Conscrypt refused to fix this issue, but even if they fixed it, there are always Android phones
  // running old versions of Conscrypt, so we decided to take matters into our own hands.
  // Why 16? Actually any number larger than 16 should work. 16 is the lower bound because it's the
  // size of the tags of each AES-GCM ciphertext segment.
  private static final int PLAINTEXT_SEGMENT_EXTRA_SIZE = 16;

  private final SeekableByteChannel ciphertextChannel;
  private final ByteBuffer ciphertextSegment;
  private final ByteBuffer plaintextSegment;
  private final ByteBuffer header;
  private final long ciphertextChannelSize;  // unverified size of the ciphertext
  private final int numberOfSegments;  // unverified number of segments
  private final int lastCiphertextSegmentSize;  // unverified size of the last segment.
  private final byte[] aad;
  private final StreamSegmentDecrypter decrypter;
  private long plaintextPosition;
  private long plaintextSize;
  private boolean headerRead;
  private boolean isCurrentSegmentDecrypted;
  private int currentSegmentNr;
  private boolean isopen;
  private final int plaintextSegmentSize;
  private final int ciphertextSegmentSize;
  private final int ciphertextOffset;
  private final int firstSegmentOffset;

  public StreamingAeadSeekableDecryptingChannel(
      NonceBasedStreamingAead streamAead,
      SeekableByteChannel ciphertext,
      byte[] associatedData) throws IOException, GeneralSecurityException {
    decrypter = streamAead.newStreamSegmentDecrypter();
    ciphertextChannel = ciphertext;
    header = ByteBuffer.allocate(streamAead.getHeaderLength());
    ciphertextSegmentSize = streamAead.getCiphertextSegmentSize();
    ciphertextSegment = ByteBuffer.allocate(ciphertextSegmentSize);
    plaintextSegmentSize = streamAead.getPlaintextSegmentSize();
    plaintextSegment = ByteBuffer.allocate(plaintextSegmentSize + PLAINTEXT_SEGMENT_EXTRA_SIZE);
    plaintextPosition = 0;
    headerRead = false;
    currentSegmentNr = -1;
    isCurrentSegmentDecrypted = false;
    ciphertextChannelSize = ciphertextChannel.size();
    aad = Arrays.copyOf(associatedData, associatedData.length);
    isopen = ciphertextChannel.isOpen();
    int  fullSegments = (int) (ciphertextChannelSize / ciphertextSegmentSize);
    int remainder = (int) (ciphertextChannelSize % ciphertextSegmentSize);
    int ciphertextOverhead = streamAead.getCiphertextOverhead();
    if (remainder > 0) {
      numberOfSegments = fullSegments + 1;
      if (remainder < ciphertextOverhead) {
        throw new IOException("Invalid ciphertext size");
      }
      lastCiphertextSegmentSize = remainder;
    } else {
      numberOfSegments = fullSegments;
      lastCiphertextSegmentSize = ciphertextSegmentSize;
    }
    ciphertextOffset = streamAead.getCiphertextOffset();
    firstSegmentOffset = ciphertextOffset - streamAead.getHeaderLength();
    if (firstSegmentOffset < 0) {
      throw new IOException("Invalid ciphertext offset or header length");
    }
    long overhead = (long) numberOfSegments * ciphertextOverhead + ciphertextOffset;
    if (overhead > ciphertextChannelSize) {
      throw new IOException("Ciphertext is too short");
    }
    plaintextSize = ciphertextChannelSize - overhead;
  }

  /**
   * A description of the state of this StreamingAeadSeekableDecryptingChannel.
   * While this description does not contain plaintext or key material
   * it contains length information that might be confidential.
   */
  @Override
  public synchronized String toString() {
    StringBuilder res =
      new StringBuilder();
    String ctChannel;
    try {
      ctChannel = "position:" + ciphertextChannel.position();
    } catch (IOException ex) {
      ctChannel = "position: n/a";
    }
    res.append("StreamingAeadSeekableDecryptingChannel")
       .append("\nciphertextChannel").append(ctChannel)
       .append("\nciphertextChannelSize:").append(ciphertextChannelSize)
       .append("\nplaintextSize:").append(plaintextSize)
       .append("\nciphertextSegmentSize:").append(ciphertextSegmentSize)
       .append("\nnumberOfSegments:").append(numberOfSegments)
       .append("\nheaderRead:").append(headerRead)
       .append("\nplaintextPosition:").append(plaintextPosition)
       .append("\nHeader")
       .append(" position:").append(header.position())
       .append(" limit:").append(header.position())
       .append("\ncurrentSegmentNr:").append(currentSegmentNr)
       .append("\nciphertextSgement")
       .append(" position:").append(ciphertextSegment.position())
       .append(" limit:").append(ciphertextSegment.limit())
       .append("\nisCurrentSegmentDecrypted:").append(isCurrentSegmentDecrypted)
       .append("\nplaintextSegment")
       .append(" position:").append(plaintextSegment.position())
       .append(" limit:").append(plaintextSegment.limit());
    return res.toString();
  }

  /**
   * Returns the position of this channel.
   * The position is relative to the plaintext.
   */
  @Override
  public synchronized long position() {
    return plaintextPosition;
  }

  /**
   * Sets the position in the plaintext.
   * Setting the position to a value greater than the plaintext size is legal.
   * A later attempt to read byte will throw an IOException.
   */
  @Override
  public synchronized SeekableByteChannel position(long newPosition) {
    plaintextPosition = newPosition;
    return this;
  }

  /**
   * Tries to read the header of the ciphertext and derive the key used for the ciphertext from the
   * information in the header.
   *
   * @return true if the header was fully read and has a correct format. Returns false if the header
   *     could not be read.
   * @throws IOException if the header was incorrectly formatted or if there was an exception during
   *     the key derivation.
   */
  private boolean tryReadHeader() throws IOException {
    ciphertextChannel.position(header.position() + firstSegmentOffset);
    ciphertextChannel.read(header);
    if (header.remaining() > 0) {
      return false;
    } else {
      header.flip();
      try {
        decrypter.init(header, aad);
        headerRead = true;
      } catch (GeneralSecurityException ex) {
        // TODO(bleichen): Define the state of this.
        throw new IOException(ex);
      }
      return true;
    }
  }

  private int getSegmentNr(long plaintextPosition) {
    return (int) ((plaintextPosition + ciphertextOffset) / plaintextSegmentSize);
  }

  /**
   * Tries to read and decrypt a ciphertext segment.
   * @param segmentNr the number of the segment
   * @return true if the segment was read and correctly decrypted.
   *          Returns false if the segment could not be fully read.
   * @throws IOException if there was an exception reading the ciphertext,
   *         if the segment number was incorrect, or
   *         if there was an exception trying to decrypt the ciphertext segment.
   */
  private boolean tryLoadSegment(int segmentNr) throws IOException {
    if (segmentNr < 0 || segmentNr >= numberOfSegments) {
      throw new IOException("Invalid position");
    }
    boolean isLast = segmentNr == numberOfSegments - 1;
    if (segmentNr == currentSegmentNr) {
      if (isCurrentSegmentDecrypted) {
        return true;
      }
    } else {
      // segmentNr != currentSegmentNr
      long ciphertextPosition = (long) segmentNr * ciphertextSegmentSize;
      int segmentSize = ciphertextSegmentSize;
      if (isLast) {
        segmentSize = lastCiphertextSegmentSize;
      }
      if (segmentNr == 0) {
        segmentSize -= ciphertextOffset;
        ciphertextPosition = ciphertextOffset;
      }
      ciphertextChannel.position(ciphertextPosition);
      ciphertextSegment.clear();
      ciphertextSegment.limit(segmentSize);
      currentSegmentNr = segmentNr;
      isCurrentSegmentDecrypted = false;
    }
    if (ciphertextSegment.remaining() > 0) {
      ciphertextChannel.read(ciphertextSegment);
    }
    if (ciphertextSegment.remaining() > 0) {
      return false;
    }
    ciphertextSegment.flip();
    plaintextSegment.clear();
    try {
      decrypter.decryptSegment(ciphertextSegment, segmentNr, isLast, plaintextSegment);
    } catch (GeneralSecurityException ex) {
      // The current segment did not validate. Ensure that this instance remains
      // in a valid state.
      currentSegmentNr = -1;
      throw new IOException("Failed to decrypt", ex);
    }
    plaintextSegment.flip();
    isCurrentSegmentDecrypted = true;
    return true;
  }

  /**
   * Returns true if plaintextPositon is at the end of the file
   * and this has been verified, by decrypting the last segment.
   */
  private boolean reachedEnd() {
    return (isCurrentSegmentDecrypted
            && currentSegmentNr == numberOfSegments - 1
            && plaintextSegment.remaining() == 0);
  }

  /**
   * Atomic read from a given position.
   *
   * This method works in the same way as read(ByteBuffer), except that it starts at the given
   * position and does not modify the channel's position.
   */
  public synchronized int read(ByteBuffer dst, long start) throws IOException {
    long oldPosition = position();
    try {
      position(start);
      return read(dst);
    } finally {
      position(oldPosition);
    }
  }

  @Override
  public synchronized int read(ByteBuffer dst) throws IOException {
    if (!isopen) {
      throw new ClosedChannelException();
    }
    if (!headerRead) {
      if (!tryReadHeader()) {
        return 0;
      }
    }
    int startPos = dst.position();
    while (dst.remaining() > 0 && plaintextPosition < plaintextSize) {
      // Determine segmentNr for the plaintext to read and the offset in
      // the plaintext, where reading should start.
      int segmentNr = getSegmentNr(plaintextPosition);
      int segmentOffset;
      if (segmentNr == 0) {
         segmentOffset = (int) plaintextPosition;
      } else {
         segmentOffset = (int) ((plaintextPosition +  ciphertextOffset) % plaintextSegmentSize);
      }

      if (tryLoadSegment(segmentNr)) {
        plaintextSegment.position(segmentOffset);
        if (plaintextSegment.remaining() <= dst.remaining()) {
          plaintextPosition += plaintextSegment.remaining();
          dst.put(plaintextSegment);
        } else {
          int sliceSize = dst.remaining();
          ByteBuffer slice = plaintextSegment.duplicate();
          slice.limit(slice.position() + sliceSize);
          dst.put(slice);
          plaintextPosition += sliceSize;
          plaintextSegment.position(plaintextSegment.position() + sliceSize);
        }
      } else {
        break;
      }
    }
    int read = dst.position() - startPos;
    if (read == 0 && reachedEnd()) {
      return -1;
    }
    return read;
  }

  /**
   * Returns the expected size of the plaintext.
   * Note that this implementation does not perform an integrity check on the size.
   * I.e. if the file has been truncated then size() will return the wrong
   * result. Reading the last block of the ciphertext will verify whether size()
   * is correct.
   */
  @Override
  public long size() {
    return plaintextSize;
  }

  public synchronized long verifiedSize() throws IOException {
    if (tryLoadSegment(numberOfSegments - 1)) {
      return plaintextSize;
    } else {
      throw new IOException("could not verify the size");
    }
  }

  @Override
  public SeekableByteChannel truncate(long size) throws NonWritableChannelException {
    throw new NonWritableChannelException();
  }

  @Override
  public int write(ByteBuffer src) throws NonWritableChannelException {
    throw new NonWritableChannelException();
  }

  @Override
  public synchronized void close() throws IOException {
    ciphertextChannel.close();
    isopen = false;
  }

  @Override
  public synchronized boolean isOpen() {
    return isopen;
  }
}
