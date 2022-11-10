/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/** Interface for private keys for Key Encapsulation Mechanism (KEM)  */
export interface HpkeKemPrivateKey {
  /** Gets the serialized KEM private key. */
  getSerializedPrivateKey(): Promise<Uint8Array>;

  /** Gets the serialized KEM public key. */
  getSerializedPublicKey(): Promise<Uint8Array>;

  /** Access to the KEM private key. */
  readonly privateKey: CryptoKey;

  /** Access to the KEM public key. */
  readonly publicKey: CryptoKey;
}
