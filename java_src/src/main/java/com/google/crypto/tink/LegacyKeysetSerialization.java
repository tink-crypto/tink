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

package com.google.crypto.tink;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Parsing and Serialization methods for use with {@link KeysetReader} and {@link KeysetWriter}
 * classes.
 *
 * <p>In combination with a {@link BinaryKeysetReader} or a {@link BinaryKeysetWriter}, the methods
 * in this file produce serializations compatible with the methods in {@link TinkProtoKeysetFormat}.
 *
 * <p>In combination with a {@link JsonKeysetReader} or a {@link JsonKeysetWriter}, the methods in
 * this file produce serializations compatible with the methods in {@link
 * TinkJsonProtoKeysetFormat}.
 */
public final class LegacyKeysetSerialization {
  /**
   * Parse a KeysetHandle from the reader.
   *
   * <p>This method is used for keysets containing no secret key material.
   */
  public static KeysetHandle parseKeysetWithoutSecret(KeysetReader reader)
      throws GeneralSecurityException, IOException {
    return KeysetHandle.readNoSecret(reader);
  }

  /**
   * Parse a keyset from the reader.
   *
   * <p>This is used to parse keysets that may contain secret key material. The second argument has
   * to be {@code InsecureSecretKeyAccess.get()}.
   */
  public static KeysetHandle parseKeyset(KeysetReader reader, SecretKeyAccess access)
      throws GeneralSecurityException, IOException {
    if (access == null) {
      throw new NullPointerException("SecretKeyAccess cannot be null");
    }
    return CleartextKeysetHandle.read(reader);
  }

  /** Parse an encrypted keyset from the reader. */
  public static KeysetHandle parseEncryptedKeyset(
      KeysetReader reader, Aead aead, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    return KeysetHandle.readWithAssociatedData(reader, aead, associatedData);
  }

  /**
   * Serialize a keyset to the writer.
   *
   * <p>This method is used for keysets containing no secret key material.
   */
  public static void serializeKeysetWithoutSecret(KeysetHandle keysetHandle, KeysetWriter writer)
      throws GeneralSecurityException, IOException {
    keysetHandle.writeNoSecret(writer);
  }

  /**
   * Serialize a keyset to the writer.
   *
   * <p>This method is used to serialize keysets that may contain secret key material. The last
   * argument must be {@code InsecureSecretKeyAccess.get()}.
   */
  public static void serializeKeyset(
      KeysetHandle keysetHandle, KeysetWriter writer, SecretKeyAccess access) throws IOException {
    if (access == null) {
      throw new NullPointerException("SecretKeyAccess cannot be null");
    }
    CleartextKeysetHandle.write(keysetHandle, writer);
  }

  /** Serialize a keyset in an encrypted format to the writer. */
  public static void serializeEncryptedKeyset(
      KeysetHandle keysetHandle, KeysetWriter writer, Aead aead, byte[] associatedData)
      throws GeneralSecurityException, IOException {
    keysetHandle.writeWithAssociatedData(writer, aead, associatedData);
  }

  private LegacyKeysetSerialization() {}
}
