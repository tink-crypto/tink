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

goog.module('tink.subtle.IndCpaCipher');

const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * Interface for symmetric key ciphers that are indistinguishable against
 * chosen-plaintext attacks.
 *
 * Security guarantees: implementation of this interface do not provide
 * authentication, thus should not be used directly, but only to construct safer
 * primitives such as {@link tink.Aead}.
 *
 * @protected
 * @record
 */
class IndCpaCipher {
  /**
   * Encrypts `plaintext`.
   *
   * @param {!Uint8Array} plaintext the plaintext to be encrypted. It must be
   *     non-null, but can also be an empty (zero-length) byte array.
   * @return {!Promise.<!Uint8Array>} resulting ciphertext
   * @throws {SecurityException}
   */
  encrypt(plaintext) {}

  /**
   * Decrypts ciphertext with associated authenticated data.
   *
   * @param {!Uint8Array} ciphertext the ciphertext to be decrypted, must be
   *     non-null.
   * @return {!Promise.<!Uint8Array>} resulting plaintext
   * @throws {SecurityException}
   */
  decrypt(ciphertext) {}
}

exports = IndCpaCipher;
