/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package walkthrough;

// [START tink_walkthrough_write_keyset]
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import java.security.GeneralSecurityException;

// [START_EXCLUDE]
/** Example that encrypts a keyset with a Key Encryption Key and JSON serializes it. */
final class WriteKeysetExample {
  private WriteKeysetExample() {}

  // [END_EXCLUDE]

  /**
   * Serializes a keyset with handle {@code keysetHandle} in JSON format; the keyset is encrypted
   * with {@code keyEncryptionAead} and {@code associatedData}.
   *
   * <p>Prerequisites for this example:
   *
   * <ul>
   *   <li>Register AEAD implementations of Tink.
   *   <li>Create a key encryption AEAD primitive. This is usually a remote AEAD provided by a Key
   *       Management Service (KMS).
   *   <li>Create a keyset and wrap it with a {@link KeysetHandle}.
   * </ul>
   *
   * @param associatedData the associated data to use for encrypting the keyset. See
   *     https://developers.google.com/tink/aead#associated_data.
   * @return the serialized keyset.
   */
  static String writeEncryptedKeyset(
      KeysetHandle keysetHandle, Aead keyEncryptionAead, byte[] associatedData)
      throws GeneralSecurityException {
    return TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(
        keysetHandle, keyEncryptionAead, associatedData);
  }
  // [END tink_walkthrough_write_keyset]
}
