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
import com.google.crypto.tink.StreamingAead;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * A helper for creating {@link StreamingAead}-primitives from keysets.
 */
final class StreamingAeadHelper implements StreamingAead {
  private final List<StreamingAead> allPrimitives;
  private final StreamingAead primary;

  /**
   * Creates a helper that uses the provided primitives for encryption
   * and decryption of data provided via channels.
   * For encryption it uses the primitive corresponding to the primary key.
   * For decryption it uses an enabled primitive that matches the given ciphertext.
   */
  public StreamingAeadHelper(List<StreamingAead> allPrimitives, StreamingAead primary)
      throws GeneralSecurityException {
    this.allPrimitives = allPrimitives;
    this.primary = primary;
  }

  @Override
  public WritableByteChannel newEncryptingChannel(
      WritableByteChannel ciphertextDestination, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return primary.newEncryptingChannel(ciphertextDestination, associatedData);
  }

  @Override
  public ReadableByteChannel newDecryptingChannel(
      ReadableByteChannel ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new ReadableByteChannelDecrypter(allPrimitives, ciphertextChannel, associatedData);
  }

  @Override
  @RequiresApi(24) // https://developer.android.com/reference/java/nio/channels/SeekableByteChannel
  public SeekableByteChannel newSeekableDecryptingChannel(
      SeekableByteChannel ciphertextChannel, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new SeekableByteChannelDecrypter(allPrimitives, ciphertextChannel, associatedData);
  }

  @Override
  public InputStream newDecryptingStream(
      InputStream ciphertextStream,
      byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return new InputStreamDecrypter(allPrimitives, ciphertextStream, associatedData);
  }

  @Override
  public OutputStream newEncryptingStream(
      OutputStream ciphertext, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return primary.newEncryptingStream(ciphertext, associatedData);
  }
}
