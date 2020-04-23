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
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.annotation.concurrent.GuardedBy;

/**
 * A decrypter for ciphertext given in a {@link InputStream}.
 */
final class InputStreamDecrypter extends InputStream {
  @GuardedBy("this")
  boolean attemptedMatching;
  @GuardedBy("this")
  InputStream matchingStream;
  @GuardedBy("this")
  InputStream ciphertextStream;

  PrimitiveSet<StreamingAead> primitives;
  byte[] associatedData;

  /**
   * Constructs a new decrypter for {@code ciphertextStream}.
   *
   * <p>The decrypter picks a matching {@code StreamingAead}-primitive from {@code primitives},
   * and uses it for decryption.  The matching happens as follows:
   * upon first {@code read()}-call each candidate primitive reads an initial portion
   * of the stream, until it can determine whether the stream matches the key of the primitive.
   * If a canditate does not match, then the stream is reset to its initial position,
   * and the next candiate can attempt matching.  The first successful candidate
   * is then used exclusively on subsequent {@code read()}-calls.
   *
   * <p> The matching process wraps {@code ciphertextStream} into a BufferedInputStream,
   * unless ciphertextStream supports rewinding (i.e. ciphertextStream.markSupported() == true).
   * Buffering of the ciphertext is disabled once a ciphertext block has been successfully
   * decrypted.
   */
  public InputStreamDecrypter(PrimitiveSet<StreamingAead> primitives,
      InputStream ciphertextStream, final byte[] associatedData) {
    this.attemptedMatching = false;
    this.matchingStream = null;
    this.primitives = primitives;
    // This class can use ciphertextStream directly if it supports mark and reset.
    if (ciphertextStream.markSupported()) {
      this.ciphertextStream = ciphertextStream;
    } else {
      this.ciphertextStream = new BufferedInputStream(ciphertextStream);
    }
    // We don't know how much ciphertext we have to cache.
    // Fortunately, BufferedInputStream only allocates memory when needed, starting
    // with an 8 kB buffer.
    // If this strategy fails, then we should add a method to the StreamingPrimitives
    // that returns the size of the ciphertext needed to decide if a key is valid.
    this.ciphertextStream.mark(Integer.MAX_VALUE);
    this.associatedData = associatedData.clone();
  }

  /**
   * Rewinds the ciphetext stream to the beginning of the ciphertext.
   */
  @GuardedBy("this")
  private void rewind() throws IOException {
    ciphertextStream.reset();
  }

  /**
   * Disable rewinding.
   * This method is called once this class has found the correct key version.
   * TODO(bleichen): While BufferedInputStream stops buffering new bytes,
   *   it does not shrink the intenal buffer.
   */
  @GuardedBy("this")
  private void disableRewinding() throws IOException {
    ciphertextStream.mark(0);
  }

  /**
   * This class does not support mark() and reset().
   * Applications that need random access to the plaintext of a long ciphertext
   * should use a SeekableByteChannelDecrypter (or SeekableDecryptingChannel).
   */
  @Override
  public boolean markSupported() {
    return false;
  }

  @Override
  @GuardedBy("this")
  public synchronized int available() throws IOException {
    if (matchingStream == null) {
      return 0;
    } else {
      return matchingStream.available();
    }
  }

  @Override
  @GuardedBy("this")
  public synchronized int read() throws IOException {
    byte[] oneByte = new byte[1];
    if (read(oneByte) == 1) {
      return oneByte[0];
    }
    return -1;
  }

  @Override
  @GuardedBy("this")
  public synchronized int read(byte[] b) throws IOException {
    return read(b, 0, b.length);
  }

  @Override
  @GuardedBy("this")
  public synchronized int read(byte[] b, int offset, int len) throws IOException {
    if (len == 0) {
      return 0;
    }
    if (matchingStream != null) {
      return matchingStream.read(b, offset, len);
    } else {
      if (attemptedMatching) {
        throw new IOException("No matching key found for the ciphertext in the stream.");
      }
      attemptedMatching = true;
      List<PrimitiveSet.Entry<StreamingAead>> entries = primitives.getRawPrimitives();
      for (PrimitiveSet.Entry<StreamingAead> entry : entries) {
        try {
          InputStream attemptedStream =
              entry.getPrimitive().newDecryptingStream(ciphertextStream, associatedData);
          int retValue = attemptedStream.read(b, offset, len);
          if (retValue == 0) {
            // Not clear whether the stream could be matched: it might be
            // that the underlying stream didn't provide sufficiently many bytes
            // to check the header, or maybe the header was checked, but there
            // were no actual encrypted bytes in the stream yet.
            // Should try again.
            rewind();
            attemptedMatching = false;
          } else {
            // Found a matching stream.
            // If retValue > 0 then the first ciphertext segment has been decrypted and
            // authenticated. If retValue == -1 then plaintext is empty and again this has been
            // authenticated.
            matchingStream = attemptedStream;
            disableRewinding();
          }
          return retValue;
        } catch (IOException e) {
          // Try another key.
          // IOException is thrown e.g. when MAC is incorrect, but also in case
          // of I/O failures.
          // TODO(b/66098906): Use a subclass of IOException.
          rewind();
          continue;
        } catch (GeneralSecurityException e) {
          // Try another key.
          rewind();
          continue;
        }
      }
      throw new IOException("No matching key found for the ciphertext in the stream.");
    }
  }

  @Override
  @GuardedBy("this")
  public synchronized void close() throws IOException {
    ciphertextStream.close();
  }
}
