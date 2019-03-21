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
import java.util.List;
import javax.annotation.concurrent.GuardedBy;

/**
 * A decrypter for ciphertext given in a {@link ReadableByteChannel}.
 */
final class ReadableByteChannelDecrypter implements ReadableByteChannel {
  @GuardedBy("this")
  boolean attemptedMatching;
  @GuardedBy("this")
  ReadableByteChannel matchingChannel;
  @GuardedBy("this")
  RewindableReadableByteChannel ciphertextChannel;

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
   *
   * <p> The matching process uses a buffering wrapper around {@code ciphertextChannel}
   * to enable resetting of the channel to the initial position.  The buffering
   * is removed once the matching is successful.
   */
  public ReadableByteChannelDecrypter(PrimitiveSet<StreamingAead> primitives,
      ReadableByteChannel ciphertextChannel, final byte[] associatedData) {
    this.attemptedMatching = false;
    this.matchingChannel = null;
    this.primitives = primitives;
    this.ciphertextChannel = new RewindableReadableByteChannel(ciphertextChannel);
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
          ReadableByteChannel attemptedChannel =
              entry.getPrimitive().newDecryptingChannel(ciphertextChannel, associatedData);
          int retValue = attemptedChannel.read(dst);
          if (retValue > 0) {
            // Found a matching channel
            matchingChannel = attemptedChannel;
            ciphertextChannel.disableRewinding();
          } else if (retValue == 0) {
            // Not clear whether the channel could be matched: it might be
            // that the underlying channel didn't provide sufficiently many bytes
            // to check the header, or maybe the header was checked, but there
            // were no actual encrypted bytes in the channel yet.
            // Should try again.
            ciphertextChannel.rewind();
            attemptedMatching = false;
          }
          return retValue;
        } catch (IOException e) {
          // Try another key.
          // IOException is thrown e.g. when MAC is incorrect, but also in case
          // of I/O failures.
          // TODO(b/66098906): Use a subclass of IOException.
          ciphertextChannel.rewind();
          continue;
        } catch (GeneralSecurityException e) {
          // Try another key.
          ciphertextChannel.rewind();
          continue;
        }
      }
      throw new IOException("No matching key found for the ciphertext in the stream.");
    }
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
