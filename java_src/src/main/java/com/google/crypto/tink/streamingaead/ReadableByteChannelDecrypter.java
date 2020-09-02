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
import com.google.crypto.tink.subtle.RewindableReadableByteChannel;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.Deque;
import javax.annotation.concurrent.GuardedBy;

/**
 * A decrypter for ciphertext given in a {@link ReadableByteChannel}.
 */
final class ReadableByteChannelDecrypter implements ReadableByteChannel {
  @GuardedBy("this")
  ReadableByteChannel attemptingChannel;
  @GuardedBy("this")
  ReadableByteChannel matchingChannel;
  @GuardedBy("this")
  RewindableReadableByteChannel ciphertextChannel;

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
   *
   * <p> The matching process uses a buffering wrapper around {@code ciphertextChannel}
   * to enable resetting of the channel to the initial position.  The buffering
   * is removed once the matching is successful.
   */
  public ReadableByteChannelDecrypter(PrimitiveSet<StreamingAead> primitives,
      ReadableByteChannel ciphertextChannel, final byte[] associatedData) {
    // There are 3 phases:
    // 1) both matchingChannel and attemptingChannel are null. Rewind is enabled.
    // 2) attemptingChannel is non-null, matchingChannel is null. Rewind is enabled.
    // 3) attemptingChannel is null, matchingChannel is non-null. Rewind is disabled.
    this.attemptingChannel = null;
    this.matchingChannel = null;
    this.remainingPrimitives = new ArrayDeque<>();
    for (PrimitiveSet.Entry<StreamingAead> entry : primitives.getRawPrimitives()) {
      this.remainingPrimitives.add(entry.getPrimitive());
    }
    this.ciphertextChannel = new RewindableReadableByteChannel(ciphertextChannel);
    this.associatedData = associatedData.clone();
  }

  @GuardedBy("this")
  private synchronized ReadableByteChannel nextAttemptingChannel() throws IOException {
    while (!remainingPrimitives.isEmpty()) {
      StreamingAead streamingAead = this.remainingPrimitives.removeFirst();
      try {
        ReadableByteChannel decChannel = streamingAead.newDecryptingChannel(
            ciphertextChannel, associatedData);
        return decChannel;
      } catch (GeneralSecurityException e) {
        // Try another primitive.
        ciphertextChannel.rewind();
      }
    }
    throw new IOException("No matching key found for the ciphertext in the stream.");
  }

  @Override
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
          ciphertextChannel.disableRewinding();
          return retValue;
        } catch (IOException e) {
          // Try another key.
          // IOException is thrown e.g. when MAC is incorrect, but also in case
          // of I/O failures.
          // TODO(b/66098906): Use a subclass of IOException.
          ciphertextChannel.rewind();
          attemptingChannel = nextAttemptingChannel();
        }
      }
    }
  }

  @Override
  public synchronized void close() throws IOException {
    ciphertextChannel.close();
  }

  @Override
  public synchronized boolean isOpen() {
    return ciphertextChannel.isOpen();
  }
}
