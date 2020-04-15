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

import com.google.crypto.tink.StreamingAead;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;

/**
 * An abstract class for StreamingAead using the nonce based online encryption scheme proposed in <a
 * href="https://eprint.iacr.org/2015/189.pdf">Online Authenticated-Encryption and its Nonce-Reuse
 * Misuse-Resistance</a> by Hoang, Reyhanitabar, Rogaway and Vizár.
 */
abstract class NonceBasedStreamingAead implements StreamingAead {

  // Abstract methods that the subclass has to implement.
  public abstract StreamSegmentEncrypter newStreamSegmentEncrypter(byte[] associatedData)
      throws GeneralSecurityException;
  // TODO(bleichen): Consider to pass aad here too.
  public abstract StreamSegmentDecrypter newStreamSegmentDecrypter()
      throws GeneralSecurityException;

  public abstract int getPlaintextSegmentSize();

  public abstract int getCiphertextSegmentSize();

  public abstract int getCiphertextOffset();

  public abstract int getCiphertextOverhead();

  public abstract int getHeaderLength();

  @Override
  public WritableByteChannel newEncryptingChannel(
      WritableByteChannel ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new StreamingAeadEncryptingChannel(this, ciphertextChannel, associatedData);
  }

  @Override
  public ReadableByteChannel newDecryptingChannel(
      ReadableByteChannel ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new StreamingAeadDecryptingChannel(this, ciphertextChannel, associatedData);
  }

  @Override
  public SeekableByteChannel newSeekableDecryptingChannel(
      SeekableByteChannel ciphertextSource, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new StreamingAeadSeekableDecryptingChannel(this, ciphertextSource, associatedData);
  }

  @Override
  public OutputStream newEncryptingStream(OutputStream ciphertext, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new StreamingAeadEncryptingStream(this, ciphertext, associatedData);
  }

  @Override
  public InputStream newDecryptingStream(InputStream ciphertextStream, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new StreamingAeadDecryptingStream(this, ciphertextStream, associatedData);
  }
}
