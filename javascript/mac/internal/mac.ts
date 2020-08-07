/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


/**
 * Interface for Message Authentication Codes (MAC).
 *
 * Security guarantees: Message Authentication Codes provide symmetric message
 * authentication. Instances implementing this interface are secure against
 * existential forgery under chosen plaintext attack, and can be deterministic
 * or randomized. This interface should be used for authentication only, and not
 * for other purposes like generation of pseudorandom bytes.
 *
 */
export abstract class Mac {
  /**
   * Computes message authentication code (MAC) for `data`.
   *
   * @param data the data to compute MAC
   * @return the MAC tag
   */
  abstract computeMac(data: Uint8Array): Promise<Uint8Array>;

  /**
   * Verifies whether `tag` is a correct authentication code for `data`.
   *
   * @param tag  the MAC tag
   * @param data the data to compute MAC
   */
  abstract verifyMac(tag: Uint8Array, data: Uint8Array): Promise<boolean>;
}
