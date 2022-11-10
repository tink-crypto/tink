/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {HpkeKemEncapOutput} from './hpke_kem_encap_output';
import {HpkeKemPrivateKey} from './hpke_kem_private_key';

/**
 * Interface for Hybrid Public Key Encryption (HPKE) key encapsulation mechanism
 * (KEM).
 *
 * HPKE RFC is available at https://www.rfc-editor.org/rfc/rfc9180.html.
 */
export interface HpkeKem {
  /**
   * Generates and encapsulates a shared secret using the `recipientPublicKey`.
   * Returns a `HpkeKemEncapOutput` object that contains the raw shared secret
   * and the encapsulated key. The HPKE RFC refers to this method as Encap(),
   * which is used by the sender.
   *
   * @throws SecurityException when either the shared secret cannot be generated
   * or the shared secret cannot be encapsulated.
   */
  encapsulate(recipientPublicKey: Uint8Array): Promise<HpkeKemEncapOutput>;

  /**
   * Extracts the shared secret from `encapsulatedKey` using
   * `recipientPrivateKey`. Returns the raw shared secret. The HPKE RFC refers
   * to this method as Decap(), which is used by the recipient.
   *
   * @throws SecurityException if the shared secret cannot be extracted.
   */
  decapsulate(
      encapsulatedKey: Uint8Array,
      recipientPrivateKey: HpkeKemPrivateKey): Promise<Uint8Array>;

  /**
   * Returns the HPKE KEM algorithm identifier for the underlying KEM
   * implementation.
   *
   * @see https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism.
   */
  getKemId(): Uint8Array;
}
