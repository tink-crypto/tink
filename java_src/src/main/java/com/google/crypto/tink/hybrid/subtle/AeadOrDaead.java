// Copyright 2020 Google LLC
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

package com.google.crypto.tink.hybrid.subtle;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.DeterministicAead;
import java.security.GeneralSecurityException;

/**
 * A wrapper class that provides the functionality of an underlying Aead or Deterministic Aead
 * primitive. This is useful for smoothing out the interface differences between those two primtives
 * for cases where it isn't critical.
 */
public class AeadOrDaead {
  private final Aead aead;
  private final DeterministicAead deterministicAead;

  public AeadOrDaead(Aead aead) {
    this.aead = aead;
    this.deterministicAead = null;
  }

  public AeadOrDaead(DeterministicAead deterministicAead) {
    this.aead = null;
    this.deterministicAead = deterministicAead;
  }

  /**
   * Encrypts {@code plaintext} with {@code associatedData} as associated authenticated data. The
   * resulting ciphertext allows for checking authenticity and integrity of associated data ({@code
   * associatedData}), but does not guarantee its secrecy.
   *
   * @param plaintext the plaintext to be encrypted. It must be non-null, but can also be an empty
   *     (zero-length) byte array
   * @param associatedData associated data to be authenticated, but not encrypted. Associated data
   *     is optional, so this parameter can be null. In this case the null value is equivalent to an
   *     empty (zero-length) byte array. For successful decryption the same associatedData must be
   *     provided along with the ciphertext.
   * @return resulting ciphertext
   */
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (aead != null) {
      return this.aead.encrypt(plaintext, associatedData);
    } else {
      return this.deterministicAead.encryptDeterministically(plaintext, associatedData);
    }
  }
  /**
   * Decrypts {@code ciphertext} with {@code associatedData} as associated authenticated data. The
   * decryption verifies the authenticity and integrity of the associated data, but there are no
   * guarantees wrt. secrecy of that data.
   *
   * @param ciphertext the plaintext to be decrypted. It must be non-null.
   * @param associatedData associated data to be authenticated. For successful decryption it must be
   *     the same as associatedData used during encryption. Can be null, which is equivalent to an
   *     empty (zero-length) byte array.
   * @return resulting plaintext
   */
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (aead != null) {
      return this.aead.decrypt(ciphertext, associatedData);
    } else {
      return this.deterministicAead.decryptDeterministically(ciphertext, associatedData);
    }
  }
}
