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

// [START tink_walkthrough_obtain_and_use_aead_primitive]
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import java.security.GeneralSecurityException;

// [START_EXCLUDE]
/** AEAD encryption/decryption example. */
final class ObtainAndUseAeadPrimitiveExample {
  private ObtainAndUseAeadPrimitiveExample() {}
  // [END_EXCLUDE]

  /**
   * Showcases obtaining an AEAD primitive from {@code keysetHandle} and encrypt/decrypt.
   *
   * <p>Prerequisites for this example:
   *
   * <ul>
   *   <li>Register AEAD implementations of Tink.
   *   <li>Create a keyset and wrap it with a {@link KeysetHandle}.
   * </ul>
   *
   * @return the result of encrypting then decrypting {@code plaintext} using {@code
   *     associatedData}, with an {@code Aead} primitive obtained from {@code keysetHandle}.
   * @throws GeneralSecurityException if any error occours.
   */
  static byte[] aeadEncryptDecrypt(
      KeysetHandle keysetHandle, byte[] plaintext, byte[] associatedData)
      throws GeneralSecurityException {
    Aead aead = keysetHandle.getPrimitive(Aead.class);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    return aead.decrypt(ciphertext, associatedData);
  }
  // [END tink_walkthrough_obtain_and_use_aead_primitive]
}
