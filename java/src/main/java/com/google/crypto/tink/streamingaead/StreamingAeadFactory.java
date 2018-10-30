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

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.StreamingAead;
import java.security.GeneralSecurityException;

/**
 * Static methods for obtaining {@link StreamingAead} instances.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * KeysetHandle keysetHandle = ...;
 * StreamingAead streamingAead = StreamingAeadFactory.getPrimitive(keysetHandle);
 * java.nio.channels.FileChannel ciphertextDestination =
 *     new FileOutputStream(ciphertextFile).getChannel();
 * byte[] aad = ...
 * WritableByteChannel encryptingChannel = s.newEncryptingChannel(ciphertextDestination, aad);
 *
 * while ( ... ) {
 *   int r = encryptingChannel.write(buffer);
 *   ...
 * }
 * encryptingChannel.close();
 * }</pre>
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset. To decrypt, the primitive tries the enabled keys from the
 * keyset to select the right key for decryption. All keys in a keyset of StreamingAead have type
 * {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 *
 * @since 1.1.0
 */
public final class StreamingAeadFactory {
  /**
   * @return a StreamingAead primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static StreamingAead getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, /* keyManager= */ null);
  }

  /**
   * @return a StreamingAead primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static StreamingAead getPrimitive(
      KeysetHandle keysetHandle,
      final KeyManager<StreamingAead> keyManager)
      throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new StreamingAeadWrapper());
    final PrimitiveSet<StreamingAead> primitives =
        Registry.getPrimitives(keysetHandle, keyManager, StreamingAead.class);
    return Registry.wrap(primitives);
  }
}
