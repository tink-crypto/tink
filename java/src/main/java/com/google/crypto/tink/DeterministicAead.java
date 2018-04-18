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

import java.security.GeneralSecurityException;

/**
 * Interface for Deterministic Authenticated Encryption with Associated Data (Deterministic AEAD).
 *
 * <p>For why this interface is desirable and some of its use cases, see for example <a
 * href="https://tools.ietf.org/html/rfc5297#section-1.3">RFC 5297 section 1.3</a>.
 *
 * <h3>Warning</h3>
 *
 * <p>Unlike {@link Aead}, implementations of this interface are not semantically secure, because
 * encrypting the same plaintex always yields the same ciphertext.
 *
 * <h3>Security guarantees</h3>
 *
 * <p>Implementations of this interface provide 128-bit security level against multi-user attacks
 * with up to 2^32 keys. That means if an adversary obtains 2^32 ciphertexts of the same message
 * encrypted under 2^32 keys, they need to do 2^128 computations to obtain a single key.
 *
 * <p>Encryption with associated data ensures authenticity (who the sender is) and integrity (the
 * data has not been tampered with) of that data, but not its secrecy. (see <a
 * href="https://tools.ietf.org/html/rfc5116">RFC 5116</a>)
 *
 * @since 1.1.0
 */
public interface DeterministicAead {
  /**
   * Deterministically encrypts {@code plaintext} with {@code associatedData} as associated
   * authenticated data.
   *
   * <p><b>Warning</b>
   *
   * <p>Encrypting the same {@code plaintext} multiple times protects the integrity of that
   * plaintext, but confidentiality is compromised to the extent that an attacker can determine that
   * the same plaintext was encrypted.
   *
   * <p>The resulting ciphertext allows for checking authenticity and integrity of associated data
   * ({@code associatedData}), but does not guarantee its secrecy.
   *
   * @return resulting ciphertext
   */
  byte[] encryptDeterministically(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException;

  /**
   * Deterministically decrypts {@code ciphertext} with {@code associatedData} as associated
   * authenticated data.
   *
   * <p>The decryption verifies the authenticity and integrity of the associated data, but there are
   * no guarantees wrt. secrecy of that data.
   *
   * @return resulting plaintext
   */
  byte[] decryptDeterministically(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException;
}
