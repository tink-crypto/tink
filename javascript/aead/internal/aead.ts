/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


/**
 * Interface for Authenticated Encryption with Associated Data (AEAD).
 *
 * Security guarantees: Implementations of this interface are secure against
 * adaptive chosen ciphertext attacks. Encryption with associated data ensures
 * authenticity (who the sender is) and integrity (the data has not been
 * tampered with) of that data, but not its secrecy.
 *
 * @see https://tools.ietf.org/html/rfc5116
 */
export abstract class Aead {
  /**
   * Encrypts `plaintext` with `opt_associatedData` as associated authenticated
   * data. The resulting ciphertext allows for checking authenticity and
   * integrity of associated data, but does not guarantee its secrecy.
   *
   * @param plaintext the plaintext to be encrypted. It must be
   *     non-null, but can also be an empty (zero-length) byte array.
   * @param opt_associatedData  optional associated data to be
   *     authenticated, but not encrypted. A null value is equivalent to an
   *     empty (zero-length) byte array. For successful decryption the same
   *     associated data must be provided along with the ciphertext.
   * @return resulting ciphertext
   *
   */
  abstract encrypt(plaintext: Uint8Array, opt_associatedData?: Uint8Array|null):
      Promise<Uint8Array>;

  /**
   * Decrypts ciphertext with associated authenticated data.
   * The decryption verifies the authenticity and integrity of the associated
   * data, but there are no guarantees wrt. secrecy of that data.
   *
   * @param ciphertext the ciphertext to be decrypted, must be
   *     non-null.
   * @param opt_associatedData  optional associated data to be
   *     authenticated. A null value is equivalent to an empty (zero-length)
   *     byte array. For successful decryption the same associated data must be
   *     provided along with the ciphertext.
   * @return resulting plaintext
   */
  abstract decrypt(
      ciphertext: Uint8Array,
      opt_associatedData?: Uint8Array|null): Promise<Uint8Array>;
}
