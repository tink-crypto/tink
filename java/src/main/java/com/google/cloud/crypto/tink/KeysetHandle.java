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

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.KeysetInfo;
import com.google.protobuf.TextFormat;

/**
 * KeysetHandle provides abstracted access to Keysets, to limit the exposure
 * of actual protocol buffers that hold sensitive key material.
 */
public final class KeysetHandle {
  /**
   * The keyset data.
   */
  private final Keyset keyset;

  /**
   * This constructor is package-private. To get a new instance, users have to use one of
   * the public factories, e.g., {@code CleartextKeysetHandle} or
   * {@code KmsEncryptedKeysetHandle}).
   */
  KeysetHandle(final Keyset keyset) {
    this.keyset = keyset;
  }

  /**
   * @returns the actual keyset data.
   */
  public Keyset getKeyset() {
    return keyset;
  }

  /**
   * Prints out the keyset but without actual key material, but only names of key types
   * and the key format proto.
   */
  public String toString() {
    return TextFormat.printToUnicodeString(Util.getKeysetInfo(keyset));
  }
}
