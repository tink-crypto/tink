/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Interface for Hybrid Public Key Encryption (HPKE) authenticated encryption
 * with associated data (AEAD).
 *
 * HPKE RFC is available at https://www.rfc-editor.org/rfc/rfc9180.html.
 */
export interface HpkeAead {
  /**
   * Performs authenticated encryption of `plaintext` and `associatedData` using
   * `key` and `nonce` according to the HPKE AEAD specification.
   *
   * @see https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption.
   */
  seal({key, nonce, plaintext, associatedData}: {
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array
  }): Promise<Uint8Array>;

  /**
   * Performs authenticated decryption of `ciphertext` and `associatedData`
   * using `key` and `nonce` according to the HPKE AEAD specification.
   *
   * @see https://www.rfc-editor.org/rfc/rfc9180.html#name-encryption-and-decryption.
   */
  open({key, nonce, ciphertext, associatedData}: {
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array
  }): Promise<Uint8Array>;

  /**
   * Returns the HPKE AEAD algorithm identifier for the underlying
   * AEAD implementation.
   *
   * @see https://www.rfc-editor.org/rfc/rfc9180.html#name-authenticated-encryption-wi.
   */
  getAeadId(): Uint8Array;

  /**
   * Returns the key length (in bytes) for this algorithm (i.e., parameter
   * 'Nk' in HPKE RFC).
   */
  getKeyLength(): number;

  /**
   * Returns the nonce length (in bytes) for this algorithm (i.e.,
   * parameter 'Nn' in HPKE RFC).
   */
  getNonceLength(): number;
}
