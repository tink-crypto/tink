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

package com.google.crypto.tink.streamingaead;

import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.StreamingAead;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.annotation.concurrent.GuardedBy;

/**
 * A decrypter for ciphertext given in a {@link SeekableByteChannel}.
 */
final class SeekableByteChannelDecrypter implements SeekableByteChannel {
  @GuardedBy("this")
  boolean attemptedMatching;
  @GuardedBy("this")
  SeekableByteChannel matchingChannel;
  @GuardedBy("this")
  SeekableByteChannel ciphertextChannel;
  @GuardedBy("this")
  long cachedPosition;    // Position to which matchingChannel should be set before 1st read();
  @GuardedBy("this")
  long startingPosition;  // Position at which the ciphertext should begin.

  PrimitiveSet<StreamingAead> primitives;
  byte[] associatedData;

  /**
   * Constructs a new decrypter for {@code ciphertextChannel}.
   *
   * <p>The decrypter picks a matching {@code StreamingAead}-primitive from {@code primitives},
   * and uses it for decryption.  The matching happens as follows:
   * upon first {@code read()}-call each candidate primitive reads an initial portion
   * of the channel, until it can determine whether the channel matches the key of the primitive.
   * If a canditate does not match, then the channel is reset to its initial position,
   * and the next candiate can attempt matching.  The first successful candidate
   * is then used exclusively on subsequent {@code read()}-calls.
   */
  public SeekableByteChannelDecrypter(PrimitiveSet<StreamingAead> primitives,
      SeekableByteChannel ciphertextChannel, final byte[] associatedData) throws IOException {
    this.attemptedMatching = false;
    this.matchingChannel = null;
    this.primitives = primitives;
    this.ciphertextChannel = ciphertextChannel;
    this.cachedPosition = -1;
    this.startingPosition = ciphertextChannel.position();
    this.associatedData = associatedData.clone();
  }

  @Override
  @GuardedBy("this")
  public synchronized int read(ByteBuffer dst) throws IOException {
    if (dst.remaining() == 0) {
      return 0;
    }
    if (matchingChannel != null) {
      return matchingChannel.read(dst);
    } else {
      if (attemptedMatching) {
        throw new IOException("No matching key found for the ciphertext in the stream.");
      }
      attemptedMatching = true;
      List<PrimitiveSet.Entry<StreamingAead>> entries = primitives.getRawPrimitives();
      for (PrimitiveSet.Entry<StreamingAead> entry : entries) {
        try {
          SeekableByteChannel attemptedChannel =
              entry.getPrimitive().newSeekableDecryptingChannel(ciphertextChannel, associatedData);
          if (cachedPosition >= 0) {  // Caller did set new position before 1st read().
            attemptedChannel.position(cachedPosition);
          }
          int retValue = attemptedChannel.read(dst);
          if (retValue > 0) {
            // Found a matching channel.
            matchingChannel = attemptedChannel;
          } else if (retValue == 0) {
            // Not clear whether the channel could be matched: it might be
            // that the underlying channel didn't provide sufficiently many bytes
            // to check the header, or maybe the header was checked, but there
            // were no actual encrypted bytes in the channel yet.
            // Should try again.
            ciphertextChannel.position(startingPosition);
            attemptedMatching = false;
          }
          matchingChannel = attemptedChannel;
          return retValue;
        } catch (IOException e) {
          // Try another key.
          // IOException is thrown e.g. when MAC is incorrect, but also in case
          // of I/O failures.
          // TODO(b/66098906): Use a subclass of IOException.
          ciphertextChannel.position(startingPosition);
          continue;
        } catch (GeneralSecurityException e) {
          // Try another key.
          ciphertextChannel.position(startingPosition);
          continue;
        }
      }
      throw new IOException("No matching key found for the ciphertext in the stream.");
    }
  }

  @Override
  @GuardedBy("this")
  public synchronized SeekableByteChannel position(long newPosition) throws IOException {
    if (matchingChannel != null) {
      matchingChannel.position(newPosition);
    } else {
      if (newPosition < 0) {
        throw new IllegalArgumentException("Position must be non-negative");
      }
      cachedPosition = newPosition;
    }
    return this;
  }

  @Override
  @GuardedBy("this")
  public synchronized long position() throws IOException {
    if (matchingChannel != null) {
      return matchingChannel.position();
    } else {
      return cachedPosition;
    }
  }

  @Override
  @GuardedBy("this")
  public synchronized long size() throws IOException {
    if (matchingChannel != null) {
      return matchingChannel.size();
    } else {
      throw new IOException("Cannot determine size before first read()-call.");
    }
  }

  @Override
  public SeekableByteChannel truncate(long size) throws IOException {
    throw new NonWritableChannelException();
  }

  @Override
  public int write(ByteBuffer src) throws IOException {
    throw new NonWritableChannelException();
  }

  @Override
  @GuardedBy("this")
  public synchronized void close() throws IOException {
    ciphertextChannel.close();
  }


  @Override
  @GuardedBy("this")
  public synchronized boolean isOpen() {
    return ciphertextChannel.isOpen();
  }
}
