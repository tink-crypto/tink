/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Aead} from '../aead/internal/aead';

/**
 * A helper for DEM (data encapsulation mechanism) of ECIES-AEAD-HKDF.
 */
export interface EciesAeadHkdfDemHelper {
  /**
   * @return the size of the DEM key in bytes
   */
  getDemKeySizeInBytes(): number;

  /**
   * Creates a new `Aead` primitive that uses the key material given in
   * `demKey`, which must be of length `getDemKeySizeInBytes()`.
   *
   * @param demKey the DEM key.
   * @return the newly created `Aead` primitive.
   */
  getAead(demKey: Uint8Array): Promise<Aead>;
}
