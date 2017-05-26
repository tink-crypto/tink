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

import com.google.crypto.tink.TinkProto.Keyset;
import com.google.crypto.tink.TinkProto.KeysetInfo;
import com.google.crypto.tink.subtle.ImmutableByteArray;
import com.google.errorprone.annotations.Immutable;

/**
 * KeysetHandle provides abstracted access to Keysets, to limit the exposure
 * of actual protocol buffers that hold sensitive key material.
 */
@Immutable
public final class KeysetHandle {
  /**
   * The {@code Keyset}.
   */
  private final Keyset keyset;

  /**
   * {@code Keyset} encrypted with some key.
   */
  private final ImmutableByteArray encryptedKeyset;

  /**
   * This constructor is package-private. To get a new instance, users have to use one of
   * the public factories, e.g., {@code CleartextKeysetHandle} or
   * {@code KmsEncryptedKeysetHandle}).
   */
  KeysetHandle(Keyset keyset) {
    this.keyset = keyset;
    this.encryptedKeyset = null;
  }

  /**
   * This constructor is package-private. To get a new instance, users have to use one of
   * the public factories, e.g., {@code CleartextKeysetHandle} or
   * {@code KmsEncryptedKeysetHandle}).
   */
  KeysetHandle(Keyset keyset, final byte[] encryptedKeyset) {
    this.keyset = keyset;
    this.encryptedKeyset = ImmutableByteArray.of(encryptedKeyset);
  }

  /**
   * @return the actual keyset data.
   */
  public Keyset getKeyset() {
    return keyset;
  }

  /**
   * @return the actual keyset data.
   */
  public KeysetInfo getKeysetInfo() {
    return Util.getKeysetInfo(keyset);
  }

  /**
   * @return the actual keyset data.
   */
  public byte[] getEncryptedKeyset() {
    if (encryptedKeyset == null) {
      return null;
    } else {
      return encryptedKeyset.getBytes();
    }
  }

  /**
   * Prints out the keyset but without actual key material, but only names of key types
   * and the key format proto.
   */
  @Override
  public String toString() {
    return getKeysetInfo().toString();
  }
}
