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

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Reads and writes cleartext keyset handles.
 *
 * <p> Reading or writing cleartext keysets is a bad practice, thus usage of this API should be
 * restricted. Users can read or write encrypted keysets with {@code KeysetHandle}.
 */
public final class CleartextKeysetHandle {
  /**
   * @return a new keyset handle from a keyset obtained from {@code reader}.
   * @throws GeneralSecurityException
   */
  public static KeysetHandle read(KeysetReader reader)
      throws GeneralSecurityException, IOException {
    return KeysetHandle.fromKeyset(reader.read());
  }

  /**
   * Serializes and writes the keyset to {@code keysetWriter}.
   */
  public static void write(KeysetHandle handle, KeysetWriter keysetWriter) throws IOException {
    keysetWriter.write(handle.getKeyset());
    return;
  }
}
