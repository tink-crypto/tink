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
 * The interface for authenticated encryption with additional authenticated data.
 * Implementations of this interface are secure against adaptive chosen ciphertext attacks.
 * Encryption with additional data ensures authenticity and integrity of that data,
 * but not its secrecy. (see RFC 5116, https://tools.ietf.org/html/rfc5116)
 */
public interface Aead {
  /**
   * Encrypts {@code plaintext} with {@code additionalData} as additional authenticated data.
   * The resulting ciphertext allows for checking authenticity and integrity
   * of additional data ({@code additionalData}), but does not guarantee its secrecy.
   *
   * @return resulting ciphertext.
   */
  byte[] encrypt(final byte[] plaintext, final byte[] additionalData)
      throws GeneralSecurityException;

  /**
   * Decrypts {@code ciphertext} with {@code additionalData} as additional authenticated data.
   * The decryption verifies the authenticity and integrity of the additional data,
   * but there are no guarantees wrt. secrecy of that data.
   *
   * @return resulting plaintext.
   */
  byte[] decrypt(final byte[] ciphertext, final byte[] additionalData)
      throws GeneralSecurityException;
}
