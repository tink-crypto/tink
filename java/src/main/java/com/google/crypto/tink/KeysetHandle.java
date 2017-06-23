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

import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.KeysetInfo;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 * KeysetHandle provides abstracted access to Keysets, to limit the exposure
 * of actual protocol buffers that hold sensitive key material.
 */
public final class KeysetHandle {
  /**
   * The {@code Keyset}.
   */
  private final Keyset keyset;

  /**
   * The {@code EncryptedKeyset}.
   */
  private final EncryptedKeyset encryptedKeyset;

  /**
   * This constructor is package-private. To get a new instance, users have to use one of
   * the public factories, e.g., {@code CleartextKeysetHandle}.
   */
  KeysetHandle(Keyset keyset) {
    this.keyset = keyset;
    this.encryptedKeyset = null;
  }

  /**
   * This constructor is package-private. To get a new instance, users have to use one of
   * the public factories, e.g., {@code EncryptedKeysetHandle}).
   */
  KeysetHandle(Keyset keyset, EncryptedKeyset encryptedKeyset) {
    this.keyset = keyset;
    this.encryptedKeyset = encryptedKeyset;
  }

  /**
   * @return the actual keyset data.
   */
  public Keyset getKeyset() {
    return keyset;
  }

  /**
   * @return the {@code KeysetInfo} that doesn't contain actual key material.
   */
  public KeysetInfo getKeysetInfo() {
    return Util.getKeysetInfo(keyset);
  }

  /**
   * @return the encrypted keyset data.
   */
  public EncryptedKeyset getEncryptedKeyset() {
    return encryptedKeyset;
  }

  /**
   * Serializes and writes the keyset to {@code outputStream}.
   */
  public void write(OutputStream outputStream) throws IOException {
    if (encryptedKeyset != null) {
      outputStream.write(encryptedKeyset.toByteArray());
      return;
    }
    outputStream.write(keyset.toByteArray());
    return;
  }

  /**
   * Prints out the {@code KeysetInfo}.
   */
  @Override
  public String toString() {
    return getKeysetInfo().toString();
  }

  /**
   * Validate that an keyset handle contains enough key material to build a keyset on, and throws
   * otherwise.
   * @throws GeneralSecurityException
   */
  public static void assertEnoughKeyMaterial(Keyset keyset) throws GeneralSecurityException {
    if (keyset == null || keyset.getKeyCount() <= 0) {
      throw new GeneralSecurityException("empty keyset");
    }
  }

}
