// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
////////////////////////////////////////////////////////////////////////////////

/**
 * Interface for symmetric key ciphers that are indistinguishable against
 * chosen-plaintext attacks.
 *
 * Security guarantees: implementation of this interface do not provide
 * authentication, thus should not be used directly, but only to construct safer
 * primitives such as {@link tink.Aead}.
 *
 */
export interface IndCpaCipher {
  /**
   * Encrypts `plaintext`.
   *
   * @param plaintext the plaintext to be encrypted. It must be
   *     non-null, but can also be an empty (zero-length) byte array.
   * @return resulting ciphertext
   * @throws {SecurityException}
   */
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;

  /**
   * Decrypts ciphertext with associated authenticated data.
   *
   * @param ciphertext the ciphertext to be decrypted, must be
   *     non-null.
   * @return resulting plaintext
   * @throws {SecurityException}
   */
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}
