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

package com.google.crypto.tink;

import com.google.crypto.tink.proto.Keyset;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Static methods for reading or writing cleartext keysets.
 *
 * <h3>WARNING</h3>
 *
 * <p>Reading or writing cleartext keysets is a bad practice, usage of this API should be
 * restricted. Users can read encrypted keysets using {@link KeysetHandle#read}.
 *
 * @since 1.0.0
 */
public final class CleartextKeysetHandle {
  /**
   * @return a new {@link KeysetHandle} from {@code serialized} that is a serialized {@link Keyset}
   * @throws GeneralSecurityException
   * @deprecated use {@link #read} instead
   */
  @Deprecated
  public static final KeysetHandle parseFrom(final byte[] serialized)
      throws GeneralSecurityException {
    try {
      Keyset keyset = Keyset.parseFrom(serialized, ExtensionRegistryLite.getEmptyRegistry());
      return KeysetHandle.fromKeyset(keyset);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("invalid keyset");
    }
  }

  /**
   * @return a new {@link KeysetHandle} from a {@link Keyset} read with {@code reader}.
   * @throws GeneralSecurityException
   */
  public static KeysetHandle read(KeysetReader reader)
      throws GeneralSecurityException, IOException {
    return KeysetHandle.fromKeyset(reader.read());
  }

  /**
   * @return the keyset underlying this {@code keysetHandle}.
   */
  public static Keyset getKeyset(KeysetHandle keysetHandle) {
    return keysetHandle.getKeyset();
  }

  /** Returns a KeysetHandle for {@code keyset}. */
  public static KeysetHandle fromKeyset(Keyset keyset) throws GeneralSecurityException {
    return KeysetHandle.fromKeyset(keyset);
  }

  /**
   * Serializes and writes the {@link Keyset} managed by {@code handle} to {@code keysetWriter}.
   *
   * @throws IOException
   */
  public static void write(KeysetHandle handle, KeysetWriter keysetWriter) throws IOException {
    keysetWriter.write(handle.getKeyset());
  }

  private CleartextKeysetHandle() {}
}
