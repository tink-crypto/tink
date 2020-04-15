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
import java.nio.channels.ClosedChannelException;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;

/**
 * An instance of {@link WritableByteChannel} that encrypts the input using a nonce based online
 * authentication scheme.
 */
class StreamingAeadEncryptingChannel implements WritableByteChannel {
  private WritableByteChannel ciphertextChannel;
  private StreamSegmentEncrypter encrypter;
  ByteBuffer ptBuffer; // contains plaintext that has not yet been encrypted.
  ByteBuffer ctBuffer; // contains ciphertext that has not been written to ciphertextChannel.
  private int plaintextSegmentSize;
  boolean open = true;

  public StreamingAeadEncryptingChannel(
      NonceBasedStreamingAead streamAead,
      WritableByteChannel ciphertextChannel,
      byte[] associatedData) throws GeneralSecurityException, IOException {
    this.ciphertextChannel = ciphertextChannel;
    encrypter = streamAead.newStreamSegmentEncrypter(associatedData);
    plaintextSegmentSize = streamAead.getPlaintextSegmentSize();
    ptBuffer = ByteBuffer.allocate(plaintextSegmentSize);
    ptBuffer.limit(plaintextSegmentSize - streamAead.getCiphertextOffset());
    ctBuffer = ByteBuffer.allocate(streamAead.getCiphertextSegmentSize());
    // At this point, ciphertextChannel might not yet be ready to receive bytes.
    // Buffering the header in ctBuffer ensures that the header will be written when writing to
    // ciphertextChannel is possible.
    ctBuffer.put(encrypter.getHeader());
    ctBuffer.flip();
    ciphertextChannel.write(ctBuffer);
  }

  @Override
  public synchronized int write(ByteBuffer pt) throws IOException {
    if (!open) {
      throw new ClosedChannelException();
    }
    if (ctBuffer.remaining() > 0) {
      ciphertextChannel.write(ctBuffer);
    }
    int startPosition = pt.position();
    while (pt.remaining() > ptBuffer.remaining()) {
      if (ctBuffer.remaining() > 0) {
        return pt.position() - startPosition;
      }
      int sliceSize = ptBuffer.remaining();
      ByteBuffer slice = pt.slice();
      slice.limit(sliceSize);
      pt.position(pt.position() + sliceSize);
      try {
        ptBuffer.flip();
        ctBuffer.clear();
        if (slice.remaining() != 0) {
          encrypter.encryptSegment(ptBuffer, slice, false, ctBuffer);
        } else {
          encrypter.encryptSegment(ptBuffer, false, ctBuffer);
        }
      } catch (GeneralSecurityException ex) {
        throw new IOException(ex);
      }
      ctBuffer.flip();
      ciphertextChannel.write(ctBuffer);
      ptBuffer.clear();
      ptBuffer.limit(plaintextSegmentSize);
    }
    ptBuffer.put(pt);
    return pt.position() - startPosition;
  }

  @Override
  public synchronized void close() throws IOException {
    if (!open) {
      return;
    }
    // TODO(bleichen): Is there a way to fully write the remaining ciphertext?
    //   The following is the strategy from java.nio.channels.Channels.writeFullyImpl
    //   I.e. try writing as long as at least one byte is written.
    while (ctBuffer.remaining() > 0) {
      int n = ciphertextChannel.write(ctBuffer);
      if (n <= 0) {
        throw new IOException("Failed to write ciphertext before closing");
      }
    }
    try {
      ctBuffer.clear();
      ptBuffer.flip();
      encrypter.encryptSegment(ptBuffer, true, ctBuffer);
    } catch (GeneralSecurityException ex) {
      // TODO(bleichen): define the state of this. E.g. open = false;
      throw new IOException(ex);
    }
    ctBuffer.flip();
    while (ctBuffer.remaining() > 0) {
      int n = ciphertextChannel.write(ctBuffer);
      if (n <= 0) {
        throw new IOException("Failed to write ciphertext before closing");
      }
    }
    ciphertextChannel.close();
    open = false;
  }

  @Override
  public boolean isOpen() {
    return open;
  }
}
