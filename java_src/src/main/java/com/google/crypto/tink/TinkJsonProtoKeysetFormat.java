// Copyright 2022 Google LLC
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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

/** Functions to parse and serialize Keyset in Tink's JSON format based on Protobufs. */
public final class TinkJsonProtoKeysetFormat {

  @SuppressWarnings("UnusedException")
  public static KeysetHandle parseKeyset(String serializedKeyset, SecretKeyAccess access)
      throws GeneralSecurityException {
    if (access == null) {
      throw new NullPointerException("SecretKeyAccess cannot be null");
    }
    try {
      return CleartextKeysetHandle.read(JsonKeysetReader.withString(serializedKeyset));
    } catch (IOException e) {
      throw new GeneralSecurityException("Parse keyset failed");
    }
  }

  @SuppressWarnings("UnusedException")
  public static String serializeKeyset(KeysetHandle keysetHandle, SecretKeyAccess access)
      throws GeneralSecurityException {
    if (access == null) {
      throw new NullPointerException("SecretKeyAccess cannot be null");
    }
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(outputStream));
      return new String(outputStream.toByteArray(), UTF_8);
    } catch (IOException e) {
      throw new GeneralSecurityException("Serialize keyset failed");
    }
  }

  @SuppressWarnings("UnusedException")
  public static KeysetHandle parseKeysetWithoutSecret(String serializedKeyset)
      throws GeneralSecurityException {
    try {
      return KeysetHandle.readNoSecret(JsonKeysetReader.withString(serializedKeyset));
    } catch (IOException e) {
      throw new GeneralSecurityException("Parse keyset failed");
    }
  }

  @SuppressWarnings("UnusedException")
  public static String serializeKeysetWithoutSecret(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      keysetHandle.writeNoSecret(JsonKeysetWriter.withOutputStream(outputStream));
      return new String(outputStream.toByteArray(), UTF_8);
    } catch (IOException e) {
      throw new GeneralSecurityException("Serialize keyset failed");
    }
  }

  @SuppressWarnings("UnusedException")
  public static KeysetHandle parseEncryptedKeyset(
      String serializedEncryptedKeyset, Aead keysetEncryptionAead, byte[] associatedData)
      throws GeneralSecurityException {
    try {
      return KeysetHandle.readWithAssociatedData(
          JsonKeysetReader.withString(serializedEncryptedKeyset),
          keysetEncryptionAead,
          associatedData);
    } catch (IOException e) {
      throw new GeneralSecurityException("Parse keyset failed");
    }
  }

  @SuppressWarnings("UnusedException")
  public static String serializeEncryptedKeyset(
      KeysetHandle keysetHandle, Aead keysetEncryptionAead, byte[] associatedData)
      throws GeneralSecurityException {
    try {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      keysetHandle.writeWithAssociatedData(
          JsonKeysetWriter.withOutputStream(outputStream), keysetEncryptionAead, associatedData);
      return new String(outputStream.toByteArray(), UTF_8);
    } catch (IOException e) {
      throw new GeneralSecurityException("Serialize keyset failed");
    }
  }

  private TinkJsonProtoKeysetFormat() {}
}
