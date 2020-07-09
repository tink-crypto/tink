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
  @GuardedBy("this")
  ByteBuffer buffer;  // Buffer for caching initial portion of baseChannel, to enable rewinding.
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
      int readBytesCount = baseChannel.read(buffer);
      if (readBytesCount > 0) {  // Copy the read bytes to destination.
        buffer.flip();
        dst.put(buffer);
      }
      return readBytesCount;
    } else {  // Subsequent read, some data might be in the buffer.
      if (buffer.remaining() >= bytesToReadCount) {
        // Copy from the buffer and advance the buffer.
        byte[] toDst = new byte[bytesToReadCount];
        buffer.get(toDst);
        dst.put(toDst);
        if (!canRewind && buffer.remaining() == 0) {
          directRead = true;
        }
        return bytesToReadCount;
      } else {
        int bytesFromBufferCount = buffer.remaining();
        int stillToReadCount = bytesToReadCount - bytesFromBufferCount;

        // Copy the remaining bytes from the current buffer to dst.
        dst.put(buffer);

        // Read the extra bytes needed, and copy them to dst.
        ByteBuffer extraBuffer = ByteBuffer.allocate(stillToReadCount);
        int readBytesCount = baseChannel.read(extraBuffer);
        if (readBytesCount > 0) {
          extraBuffer.flip();
          dst.put(extraBuffer);
        }

        // If rewind still suported, update the buffer...
        if (canRewind) {
          int newBufferSize = buffer.limit() + stillToReadCount;
          // Allocate a larger buffer and copy the entire current buffer.
          ByteBuffer newBuffer = ByteBuffer.allocate(newBufferSize);
          buffer.flip();
          newBuffer.put(buffer);
          if (readBytesCount > 0) {
            extraBuffer.flip();
            newBuffer.put(extraBuffer);
          }
          // Record that all buffered data has been consumed already.
          newBuffer.flip();
          newBuffer.position(newBuffer.limit());
          buffer = newBuffer;
        } else {  // ... otherwise free the buffer memory.
          buffer = null;
          directRead = true;
        }

        return bytesFromBufferCount + readBytesCount;
      }
    }
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
