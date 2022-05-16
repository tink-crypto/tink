// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.hybrid.internal;

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Interface for Hybrid Public Key Encryption (HPKE) authenticated encryption with associated data
 * (AEAD).
 *
 * <p>HPKE RFC is available at https://www.rfc-editor.org/rfc/rfc9180.html.
 */
@Immutable
interface HpkeAead {
  /**
   * Performs authenticated encryption of {@code plaintext} and {@code associatedData} using {@code
   * key} and {@code nonce} according to the HPKE AEAD specification.
   *
   * <p>More details available at
   * https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption.
   */
  byte[] seal(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData)
      throws GeneralSecurityException;

  /**
   * Performs authenticated decryption of {@code ciphertext} and {@code associatedData} using {@code
   * key} and {@code nonce} according to the HPKE AEAD specification.
   *
   * <p>More details available at
   * https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption.
   */
  byte[] open(byte[] key, byte[] nonce, byte[] ciphertext, byte[] associatedData)
      throws GeneralSecurityException;

  /**
   * Returns the HPKE AEAD algorithm identifier for the underlying AEAD implementation.
   *
   * <p>More details at
   * https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi.
   */
  byte[] getAeadId() throws GeneralSecurityException;

  /** Returns key length (in bytes) for this algorithm (i.e., parameter 'Nk' in HPKE RFC). */
  int getKeyLength();

  /** Returns nonce length (in bytes) for this algorithm (i.e., parameter 'Nn' in HPKE RFC). */
  int getNonceLength();
}
