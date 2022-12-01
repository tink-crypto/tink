/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Aead} from '../aead/internal/aead';
import {InsecureIvAesGcm, IV_SIZE_IN_BYTES} from '../aead/internal/insecure_iv_aes_gcm';

import {randBytes} from './random';
import * as validators from './validators';

/**
 * Implementation of AES-GCM, wrapped around InsecureIvAesGcm.
 *
 * @final
 */
export class AesGcm extends Aead {
  private readonly insecureIvAesGcm: InsecureIvAesGcm;

  constructor(readonly key: CryptoKey) {
    super();
    this.insecureIvAesGcm = new InsecureIvAesGcm({key, prependIv: true});
  }

  async encrypt(plaintext: Uint8Array, associatedData?: Uint8Array):
      Promise<Uint8Array> {
    const iv: Uint8Array = randBytes(IV_SIZE_IN_BYTES);
    return this.insecureIvAesGcm.encrypt(iv, plaintext, associatedData);
  }

  async decrypt(ciphertext: Uint8Array, associatedData?: Uint8Array):
      Promise<Uint8Array> {
    const iv = new Uint8Array(IV_SIZE_IN_BYTES);
    iv.set(ciphertext.subarray(0, IV_SIZE_IN_BYTES));
    return this.insecureIvAesGcm.decrypt(iv, ciphertext, associatedData);
  }
}

/** Returns an AEAD instantiation genererated from a given raw `key`  */
export async function fromRawKey(key: Uint8Array): Promise<Aead> {
  validators.validateAesKeySize(key.length);
  const webCryptoKey = await self.crypto.subtle.importKey(
      /* format */
      'raw', key,
      /* keyData */
      {'name': 'AES-GCM', 'length': key.length},
      /* algo */
      false,
      /* extractable*/
      ['encrypt', 'decrypt']);

  /* usage */
  return new AesGcm(webCryptoKey);
}
