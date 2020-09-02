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

import static java.lang.Math.max;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import javax.annotation.concurrent.GuardedBy;

/**
 * A wrapper around {@link ReadableByteChannel} that provides rewinding feature: it caches the read
 * bytes so that after reading some initial part of the channel, one can "rewind" the channel and
 * again read the bytes from the beginning. Once the rewinding feature is not needed any more, it
 * can be disabled via {@link #disableRewinding}: this frees the cache memory and forwadrds the
 * subsequent {@link #read}-calls directly to the wrapped channel.
 *
 * @since 1.1.0
 */
public final class RewindableReadableByteChannel implements ReadableByteChannel {
  @GuardedBy("this")
  final ReadableByteChannel baseChannel;
  // Buffer for caching initial portion of baseChannel, to enable rewinding.
  // A non-null buffer is always in "draining" mode at the beginning and end of a read call.
  @GuardedBy("this")
  ByteBuffer buffer;
  @GuardedBy("this")
  boolean canRewind;  // True iff this channel still has rewinding enabled.
  @GuardedBy("this")
  boolean directRead;  // True iff the read-operations should go directly to baseChannel.

  /**
   * Constructs a wrapper around {@code baseChannel}.
   * After wrapping {@code baseChannel} should not be manipulated externally.
   */
  public RewindableReadableByteChannel(ReadableByteChannel baseChannel) {
    this.baseChannel = baseChannel;
    this.buffer = null;
    this.canRewind = true;
    this.directRead = false;
  }

  /**
   * Disables the rewinding feature.  After calling this method the
   * attempts to rewind this channel will fail, and the subsequent
   * read()-calls will be forwarded directly to the wrapped
   * channel (after the currently buffered bytes are read).
   */
  public synchronized void disableRewinding() {
    this.canRewind = false;
  }

  /**
   * Rewinds this buffer to the beginning (if rewinding is still enabled).
   */
  public synchronized void rewind() throws IOException {
    if (!canRewind) {
      throw new IOException("Cannot rewind anymore.");
    }
    if (buffer != null) {
      buffer.position(0);
    }
  }

  /**
   * Sets a new limit to the buffer. If the buffer does not have enough capacity, it creates a new
   * buffer with at least twice the capacity, and copies data and position of the old buffer.
   * buffer is expected to be in draining mode before this call.
   */
  private synchronized void setBufferLimit(int newLimit) {
    if (buffer.capacity() < newLimit) {
      int pos = buffer.position();
      int newBufferCapacity = max(2 * buffer.capacity(), newLimit);
      ByteBuffer newBuffer = ByteBuffer.allocate(newBufferCapacity);
      buffer.rewind();
      newBuffer.put(buffer);
      newBuffer.position(pos);
      buffer = newBuffer;
    }
    buffer.limit(newLimit);
  }

  @Override
  public synchronized int read(ByteBuffer dst) throws IOException {
    if (directRead) {
      return baseChannel.read(dst);
    }
    int bytesToReadCount = dst.remaining();
    if (bytesToReadCount == 0) {
      return 0;
    }
    if (buffer == null) {  // The first read, no cached data yet.
      if (!canRewind) {
        directRead = true;
        return baseChannel.read(dst);
      }
      buffer = ByteBuffer.allocate(bytesToReadCount);
      int baseReadResult = baseChannel.read(buffer);
      // put buffer in draining mode
      buffer.flip();
      if (baseReadResult > 0) {
        dst.put(buffer);
      }
      return baseReadResult;
    }
    // Subsequent read
    if (buffer.remaining() >= bytesToReadCount) {
      // buffer has all data needed.
      // dst.put expects buffer.remaining() <= dst.remaining(). So we have to temporarily lower
      // buffer.limit. Note that
      // buffer.position() + bytesToReadCount <= buffer.position() + buffer.remaining()
      // = buffer.position() + buffer.limit() - buffer.position() = buffer.limit().
      int limit = buffer.limit();
      buffer.limit(buffer.position() + bytesToReadCount);
      dst.put(buffer);
      buffer.limit(limit);
      if (!canRewind && !buffer.hasRemaining()) {
        buffer = null;
        directRead = true;
      }
      return bytesToReadCount;
    }
    int bytesFromBufferCount = buffer.remaining();
    int stillToReadCount = bytesToReadCount - bytesFromBufferCount;

    // buffer is in draining mode.
    int currentReadPos = buffer.position();
    int contentLimit = buffer.limit();
    // Put the buffer into into filling mode by hand. The filling should start right after the
    // current limit, and at most stillToReadCount bytes should be written.
    setBufferLimit(contentLimit + stillToReadCount);
    buffer.position(contentLimit);
    int baseReadResult = baseChannel.read(buffer);
    // Put buffer in draining mode.
    buffer.flip();
    buffer.position(currentReadPos); // restore reading position.
    dst.put(buffer);
    if (bytesFromBufferCount == 0 && baseReadResult < 0) {
      return -1;  // EOF
    }
    int bytesCount = buffer.position() - currentReadPos;
    if (!canRewind && !buffer.hasRemaining()) {
      buffer = null;
      directRead = true;
    }
    return bytesCount;
  }

  @Override
  public synchronized void close() throws IOException {
    canRewind = false;
    directRead = true;
    baseChannel.close();
  }

  @Override
  public synchronized boolean isOpen() {
    return baseChannel.isOpen();
  }
}
