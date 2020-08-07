/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


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
