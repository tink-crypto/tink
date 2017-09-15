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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.SecureRandom;

/**
 * Helpers for streaming tests.
 *
 * Some methods cannot be in TestUtil because they depend on java.nio.file which is only
 * available on Android O or newer.
 */
public class StreamingTestUtil {
  /**
   * Implements a SeekableByteChannel for testing.
   *
   * The implementation is backed by a ByteBuffer.
   */
  public static class ByteBufferChannel implements SeekableByteChannel {
    private final ByteBuffer buffer;

    /**
     * Defines the maximal size of a chunk that is transferred with a single write. This can be
     * used to test the behavior of streaming encryption with channels where not always
     * sufficiently many bytes are available during reads and writes.
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
    public synchronized ByteBufferChannel position(long newPosition)
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

  /** Generates and returns a random, temporary file path. */
  public static Path generateRandomPath(String prefix) {
    String tmpDir = java.lang.System.getenv("TEST_TMPDIR");
    String tmpFilename = String.format("%s.%s.tmp", prefix, new SecureRandom().nextLong());
    return FileSystems.getDefault().getPath(tmpDir, tmpFilename);
  }
}
