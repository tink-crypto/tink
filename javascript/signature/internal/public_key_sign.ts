// Copyright 2018 Google LLC
/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


/**
 * Interface for creating digital signatures.
 *
 * Security guarantees: Implementations of these interfaces are secure
 * against adaptive chosen-message attacks. Signing data ensures the
 * authenticity and the integrity of that data, but not its secrecy.
 *
 */
export abstract class PublicKeySign {
  /**
   * Computes the digital signature of `message`.
   *
   * @param message the message to be signed, must be non-null.
   * @return resulting digital signature
   */
  abstract sign(message: Uint8Array): Promise<Uint8Array>;
}
