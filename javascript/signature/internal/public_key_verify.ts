// Copyright 2018 Google LLC
/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


/**
 * Interface for verifying digital signatures.
 *
 * Security guarantees: Implementations of these interfaces are secure
 * against adaptive chosen-message attacks. Signing data ensures the
 * authenticity and the integrity of that data, but not its secrecy.
 *
 */
export abstract class PublicKeyVerify {
  /**
   * Verifies the `signature` of `message`.
   *
   * @param signature the signature, must be non-null.
   * @param message the message, must be non-null.
   * @return true iff the signature is valid, false
   *     otherwise.
   */
  abstract verify(signature: Uint8Array, message: Uint8Array): Promise<boolean>;
}
