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

// [START tink_walkthrough_load_cleartext_keyset]
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import java.security.GeneralSecurityException;

// [START_EXCLUDE]
/** Example that reads a JSON serialized keyset. */
final class ReadCleartextKeysetExample {
  private ReadCleartextKeysetExample() {}

  // [END_EXCLUDE]

  /**
   * Deserializes a JSON serialized keyset {@code serializedKeyset}; the keyset is in cleartext.
   *
   * <p>Prerequisites for this example:
   *
   * <ul>
   *   <li>Create a keyset and serialize it as JSON.
   * </ul>
   *
   * @return the serialized keyset.
   */
  static KeysetHandle readKeyset(String serializedKeyset) throws GeneralSecurityException {
    // NOTE: If the keyset does not contain secrets it is possible to parse without a
    // SecretKeyAccess token using TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret().
    return TinkJsonProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
  }
  // [END tink_walkthrough_load_cleartext_keyset]
}
