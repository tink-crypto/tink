/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Interface that wraps output from HPKE KEM Encap() method.
 */
export interface HpkeKemEncapOutput {
  readonly sharedSecret: Uint8Array;
  readonly encapsulatedKey: Uint8Array;
}
