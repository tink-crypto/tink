/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Interface for Hybrid Public Key Encryption (HPKE) key derivation function
 * (KDF).
 *
 * HPKE RFC is available at https://www.rfc-editor.org/rfc/rfc9180.html.
 */

export interface HpkeKdf {
  /**
   * Extracts pseudorandom key from `salt` and `ikm` using the
   * HPKE-specific values `ikmLabel` and `suiteId` to facilitate domain
   * separation and context binding.
   *
   * More details available at
   * https://www.rfc-editor.org/rfc/rfc9180.html#section-4-9.
   *
   */
  labeledExtract({ikm, ikmLabel, suiteId, salt}: {
    ikm: Uint8Array,
    ikmLabel: string,
    suiteId: Uint8Array,
    salt?: Uint8Array
  }): Promise<Uint8Array>;

  /**
   * Expands pseudorandom key `prk` into `length` pseudorandom bytes
   * using `info` along with the HPKE-specific values `infoLabel`
   * and `suiteId` to facilitate domain separation and context binding.
   *
   * More details available at
   * https://www.rfc-editor.org/rfc/rfc9180.html#section-4-10.
   *
   */
  labeledExpand({prk, info, infoLabel, suiteId, length}: {
    prk: Uint8Array,
    info: Uint8Array,
    infoLabel: string,
    suiteId: Uint8Array,
    length: number
  }): Promise<Uint8Array>;

  /**
   * Combines `labeledExtract` and `labeledExpand` into a single method.
   *
   * More details available at
   * https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1-3.
   *
   */
  extractAndExpand({ikm, ikmLabel, info, infoLabel, suiteId, length, salt}: {
    ikm: Uint8Array,
    ikmLabel: string,
    info: Uint8Array,
    infoLabel: string,
    suiteId: Uint8Array,
    length: number,
    salt?: Uint8Array
  }): Promise<Uint8Array>;

  /**
   * Returns the HPKE KDF algorithm identifier for the underlying
   * KDF implementation.
   *
   * More details at
   * https://www.rfc-editor.org/rfc/rfc9180.html#name-key-derivation-functions-kd.
   */
  getKdfId(): Uint8Array;
}
