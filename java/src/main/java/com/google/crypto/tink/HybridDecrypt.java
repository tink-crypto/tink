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
 * The interface for hybrid decryption.
 * <p>
 * Implementations of this interface are secure against adaptive chosen ciphertext attacks.
 * In addition to {@code plaintext} the encryption takes an extra parameter {@code contextInfo},
 * which usually is public data implicit from the context, but should be bound to the resulting
 * ciphertext, i.e. the ciphertext allows for checking the integrity of {@code contextInfo}
 * (but there are no guarantees wrt. to secrecy or authenticity of {@code contextInfo}).
 * <p>
 * {@code contextInfo} can be empty or null, but to ensure the correct decryption of the resulting
 * ciphertext the same value must be provided for decryption operation (cf. {@link HybridEncrypt}).
 * <p>
 * A concrete instantiation of this interface can implement the binding of {@code contextInfo}
 * to the ciphertext in various ways, for example:
 * <ul>
 *   <li> use {@code contextInfo} as "associated data"-input for the employed AEAD
 *       symmetric encryption (cf. https://tools.ietf.org/html/rfc5116). </li>
 *   <li> use {@code contextInfo} as "CtxInfo"-input for HKDF (if the implementation uses
 *       HKDF as key derivation function, cf. https://tools.ietf.org/html/rfc5869). </li>
 * </ul>
 */
public interface HybridDecrypt {
  /**
   * Decryption operation:
   * decrypts {@code ciphertext} verifying the integrity of {@code contextInfo}.
   *
   * @return resulting plaintext.
   */
  byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException;
}
