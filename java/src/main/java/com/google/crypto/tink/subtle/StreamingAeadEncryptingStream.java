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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * An instance of {@link FilterOutputStream} that encrypts the input using a nonce based online
 * authentication scheme.
 */
class StreamingAeadEncryptingStream extends FilterOutputStream {
  private StreamSegmentEncrypter encrypter;
  private int plaintextSegmentSize;
  ByteBuffer ptBuffer; // contains plaintext that has not yet been encrypted.
  ByteBuffer ctBuffer; // used for the ciphertext (does not buffer anything).
  boolean open;

  public StreamingAeadEncryptingStream(
      NonceBasedStreamingAead streamAead, OutputStream ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    super(ciphertextChannel);
    encrypter = streamAead.newStreamSegmentEncrypter(associatedData);
    plaintextSegmentSize = streamAead.getPlaintextSegmentSize();
    ptBuffer = ByteBuffer.allocate(plaintextSegmentSize);
    ctBuffer = ByteBuffer.allocate(streamAead.getCiphertextSegmentSize());
    ptBuffer.limit(plaintextSegmentSize - streamAead.getCiphertextOffset());
    ByteBuffer header = encrypter.getHeader();
    byte[] headerBytes = new byte[header.remaining()];
    header.get(headerBytes);
    out.write(headerBytes);
    open = true;
  }

  @Override
  public void write(int b) throws IOException {
    write(new byte[] {(byte) b});
  }

  @Override
  public void write(byte[] b) throws IOException {
    write(b, 0, b.length);
  }

  // TODO(bleichen): Mabye implement write(ByteBuffer) so that
  //   there are no surprises if the underlying class is extended.

  @Override
  public synchronized void write(byte[] pt, int offset, int length) throws IOException {
    if (!open) {
      throw new IOException("Trying to write to closed stream");
    }
    int startPosition = offset;
    int remaining = length;
    while (remaining > ptBuffer.remaining()) {
      int sliceSize = ptBuffer.remaining();
      ByteBuffer slice = ByteBuffer.wrap(pt, startPosition, sliceSize);
      startPosition += sliceSize;
      remaining -= sliceSize;
      try {
        ptBuffer.flip();
        ctBuffer.clear();
        encrypter.encryptSegment(ptBuffer, slice, false, ctBuffer);
      } catch (GeneralSecurityException ex) {
        throw new IOException(ex);
      }
      ctBuffer.flip();
      out.write(ctBuffer.array(), ctBuffer.position(), ctBuffer.remaining());
      ptBuffer.clear();
      ptBuffer.limit(plaintextSegmentSize);
    }
    ptBuffer.put(pt, startPosition, remaining);
  }

  @Override
  public synchronized void close() throws IOException {
    if (!open) {
      return;
    }
    try {
      ptBuffer.flip();
      ctBuffer.clear();
      encrypter.encryptSegment(ptBuffer, true, ctBuffer);
    } catch (GeneralSecurityException ex) {
      // TODO(bleichen): define the state of this. E.g. open = false;
      throw new IOException(
          "ptBuffer.remaining():"
              + ptBuffer.remaining()
              + " ctBuffer.remaining():"
              + ctBuffer.remaining(),
          ex);
    }
    ctBuffer.flip();
    out.write(ctBuffer.array(), ctBuffer.position(), ctBuffer.remaining());
    open = false;
    super.close();
  }
}
