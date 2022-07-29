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

import androidx.annotation.RequiresApi;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.StreamingAead;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.Deque;
import javax.annotation.concurrent.GuardedBy;

/** A decrypter for ciphertext given in a {@link SeekableByteChannel}. */
@RequiresApi(24) // https://developer.android.com/reference/java/nio/channels/SeekableByteChannel
final class SeekableByteChannelDecrypter implements SeekableByteChannel {
  @GuardedBy("this")
  SeekableByteChannel attemptingChannel;
  @GuardedBy("this")
  SeekableByteChannel matchingChannel;
  @GuardedBy("this")
  SeekableByteChannel ciphertextChannel;
  @GuardedBy("this")
  long cachedPosition;    // Position to which attemptingChannel should be set before 1st read();
  @GuardedBy("this")
  long startingPosition;  // Position at which the ciphertext should begin.

  // The StreamingAeads that have not yet been tried in nextAttemptingChannel.
  Deque<StreamingAead> remainingPrimitives;
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
    // There are 3 phases:
    // 1) both matchingChannel and attemptingChannel are null.
    // 2) attemptingChannel is non-null, matchingChannel is null
    // 3) attemptingChannel is null, matchingChannel is non-null.
    this.attemptingChannel = null;
    this.matchingChannel = null;
    this.remainingPrimitives = new ArrayDeque<>();
    for (PrimitiveSet.Entry<StreamingAead> entry : primitives.getRawPrimitives()) {
      this.remainingPrimitives.add(entry.getPrimitive());
    }
    this.ciphertextChannel = ciphertextChannel;
    // In phase 1) and 2), cachedPosition is always equal to the last position value set.
    // In phase 2), attemptingChannel always has its position set to cachedPosition.
    // In phase 3), cachedPosition is not needed.
    this.cachedPosition = -1;
    this.startingPosition = ciphertextChannel.position();
    this.associatedData = associatedData.clone();
  }

  @GuardedBy("this")
  private synchronized SeekableByteChannel nextAttemptingChannel() throws IOException {
    while (!remainingPrimitives.isEmpty()) {
      ciphertextChannel.position(startingPosition);
      StreamingAead streamingAead = this.remainingPrimitives.removeFirst();
      try {
        SeekableByteChannel decChannel =
            streamingAead.newSeekableDecryptingChannel(ciphertextChannel, associatedData);
        if (cachedPosition >= 0) { // Caller already set new position.
          decChannel.position(cachedPosition);
        }
        return decChannel;
      } catch (GeneralSecurityException e) {
        // Try another primitive.
      }
    }
    throw new IOException("No matching key found for the ciphertext in the stream.");
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
      if (attemptingChannel == null) {
        attemptingChannel = nextAttemptingChannel();
      }
      while (true) {
        try {
          int retValue = attemptingChannel.read(dst);
          if (retValue == 0) {
            // No data at the moment. Not clear if decryption was successful.
            // Try again with the same stream next time.
            return 0;
          }
          // Found a matching channel.
          matchingChannel = attemptingChannel;
          attemptingChannel = null;
          return retValue;
        } catch (IOException e) {
          // Try another key.
          // IOException is thrown e.g. when MAC is incorrect, but also in case
          // of I/O failures.
          // TODO(b/66098906): Use a subclass of IOException.
          attemptingChannel = nextAttemptingChannel();
        }
      }
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
      if (attemptingChannel != null) {
        attemptingChannel.position(cachedPosition);
      }
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
