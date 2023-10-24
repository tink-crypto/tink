// Copyright 2023 Google LLC
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

package com.google.crypto.tink.streamingaead.internal;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.internal.LegacyProtoKey;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.proto.KeyData;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;

/**
 * Takes an arbitrary raw StreamingAead and makes it a full primitive. ("Full" doesn't make much
 * difference in case of Streaming AEADs, but we keep the name and the wrapper structure for
 * consistency with the other primitives.) This is a class that helps us transition onto the new
 * Keys and Configurations interface, by bringing potential user-defined primitives to a common
 * denominator with our primitives over which we have control.
 */
public class LegacyFullStreamingAead implements StreamingAead {

  private final StreamingAead rawStreamingAead;

  /** Covers the cases where users created their own streaming AEAD / key classes. */
  public static StreamingAead create(LegacyProtoKey key) throws GeneralSecurityException {
    /* Here we don't check that the key is RAW since, for legacy reasons,
     * StreamingAeadWrapper / KeyTypeManager don't. */
    ProtoKeySerialization protoKeySerialization =
        key.getSerialization(InsecureSecretKeyAccess.get());
    KeyData keyData =
        KeyData.newBuilder()
            .setTypeUrl(protoKeySerialization.getTypeUrl())
            .setValue(protoKeySerialization.getValue())
            .setKeyMaterialType(protoKeySerialization.getKeyMaterialType())
            .build();
    return new LegacyFullStreamingAead(Registry.getPrimitive(keyData, StreamingAead.class));
  }

  private LegacyFullStreamingAead(StreamingAead rawStreamingAead) {
    this.rawStreamingAead = rawStreamingAead;
  }

  @Override
  public WritableByteChannel newEncryptingChannel(
      WritableByteChannel ciphertextDestination, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return rawStreamingAead.newEncryptingChannel(ciphertextDestination, associatedData);
  }

  @Override
  public SeekableByteChannel newSeekableDecryptingChannel(
      SeekableByteChannel ciphertextSource, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return rawStreamingAead.newSeekableDecryptingChannel(ciphertextSource, associatedData);
  }

  @Override
  public ReadableByteChannel newDecryptingChannel(
      ReadableByteChannel ciphertextSource, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return rawStreamingAead.newDecryptingChannel(ciphertextSource, associatedData);
  }

  @Override
  public OutputStream newEncryptingStream(OutputStream ciphertextDestination, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return rawStreamingAead.newEncryptingStream(ciphertextDestination, associatedData);
  }

  @Override
  public InputStream newDecryptingStream(InputStream ciphertextSource, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return rawStreamingAead.newDecryptingStream(ciphertextSource, associatedData);
  }
}
