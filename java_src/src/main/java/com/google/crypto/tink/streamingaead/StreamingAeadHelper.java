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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;

/**
 * A helper for creating {@link StreamingAead}-primitives from keysets.
 */
final class StreamingAeadHelper implements StreamingAead {
  PrimitiveSet<StreamingAead> primitives;

  /**
   * Creates a helper that uses the provided primitives for encryption
   * and decryption of data provided via channels.
   * For encryption it uses the primitive corresponding to the primary key.
   * For decryption it uses an enabled primitive that matches the given ciphertext.
   */
  public StreamingAeadHelper(PrimitiveSet<StreamingAead> primitives)
      throws GeneralSecurityException {
    if (primitives.getPrimary() == null) {
      throw new GeneralSecurityException("Missing primary primitive.");
    }
    this.primitives = primitives;
  }

  @Override
  public WritableByteChannel newEncryptingChannel(
      WritableByteChannel ciphertextDestination, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return primitives.getPrimary().getPrimitive()
        .newEncryptingChannel(ciphertextDestination, associatedData);
  }

  @Override
  public ReadableByteChannel newDecryptingChannel(
      ReadableByteChannel ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new ReadableByteChannelDecrypter(primitives, ciphertextChannel, associatedData);
  }

  @Override
  @RequiresApi(24) // https://developer.android.com/reference/java/nio/channels/SeekableByteChannel
  public SeekableByteChannel newSeekableDecryptingChannel(
      SeekableByteChannel ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new SeekableByteChannelDecrypter(primitives, ciphertextChannel, associatedData);
  }

  @Override
  public InputStream newDecryptingStream(
      InputStream ciphertextStream,
      byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new InputStreamDecrypter(primitives, ciphertextStream, associatedData);
  }

  @Override
  public OutputStream newEncryptingStream(
      OutputStream ciphertext, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return primitives.getPrimary().getPrimitive()
        .newEncryptingStream(ciphertext, associatedData);
  }
}
