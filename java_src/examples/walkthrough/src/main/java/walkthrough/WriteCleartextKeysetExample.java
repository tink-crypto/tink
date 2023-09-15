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

// [START tink_walkthrough_write_cleartext_keyset]
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import java.security.GeneralSecurityException;

// [START_EXCLUDE]
/** Example that JSON serializes a keyset. */
final class WriteCleartextKeysetExample {
  private WriteCleartextKeysetExample() {}

  // [END_EXCLUDE]

  /**
   * Serializes a keyset with handle {@code keysetHandle} in JSON formatå.
   *
   * <p>Prerequisites for this example:
   *
   * <ul>
   *   <li>Create a keyset and wrap it with a {@link KeysetHandle}.
   * </ul>
   *
   * @return the serialized keyset.
   */
  static String writeKeyset(KeysetHandle keysetHandle) throws GeneralSecurityException {
    // NOTE: If the keyset does not contain secrets it is possible to serialize without a
    // SecretKeyAccess token using TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret().
    return TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle, InsecureSecretKeyAccess.get());
  }
  // [END tink_walkthrough_write_cleartext_keyset]
}
