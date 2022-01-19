/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';

import * as Bytes from './bytes';
import {IndCpaCipher} from './ind_cpa_cipher';
import * as Random from './random';
import * as Validators from './validators';

/**
 * The minimum IV size.
 *
 */
const MIN_IV_SIZE_IN_BYTES: number = 12;

/**
 * AES block size.
 *
 */
const AES_BLOCK_SIZE_IN_BYTES: number = 16;

/**
 * Implementation of AES-CTR.
 *
 * @final
 */
export class AesCtr implements IndCpaCipher {
  /**
   * @param ivSize the size of the IV
   */
  constructor(
      private readonly key: CryptoKey, private readonly ivSize: number) {}

  /**
   */
  async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    Validators.requireUint8Array(plaintext);
    const iv = Random.randBytes(this.ivSize);
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(iv);
    const alg = {'name': 'AES-CTR', 'counter': counter, 'length': 128};
    const ciphertext =
        await self.crypto.subtle.encrypt(alg, this.key, plaintext);
    return Bytes.concat(iv, new Uint8Array(ciphertext));
  }

  /**
   */
  async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    Validators.requireUint8Array(ciphertext);
    if (ciphertext.length < this.ivSize) {
      throw new SecurityException('ciphertext too short');
    }
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(ciphertext.subarray(0, this.ivSize));
    const alg = {'name': 'AES-CTR', 'counter': counter, 'length': 128};
    return new Uint8Array(await self.crypto.subtle.decrypt(
        alg, this.key, new Uint8Array(ciphertext.subarray(this.ivSize))));
  }
}

/**
 * @param ivSize the size of the IV, must be larger than or equal to
 *     {@link MIN_IV_SIZE_IN_BYTES}
 */
export async function fromRawKey(
    key: Uint8Array, ivSize: number): Promise<IndCpaCipher> {
  if (!Number.isInteger(ivSize)) {
    throw new SecurityException('invalid IV length, must be an integer');
  }
  if (ivSize < MIN_IV_SIZE_IN_BYTES || ivSize > AES_BLOCK_SIZE_IN_BYTES) {
    throw new SecurityException(
        'invalid IV length, must be at least ' + MIN_IV_SIZE_IN_BYTES +
        ' and at most ' + AES_BLOCK_SIZE_IN_BYTES);
  }
  Validators.requireUint8Array(key);
  Validators.validateAesKeySize(key.length);
  const cryptoKey = await self.crypto.subtle.importKey(
      'raw', key, {'name': 'AES-CTR', 'length': key.length}, false,
      ['encrypt', 'decrypt']);
  return new AesCtr(cryptoKey, ivSize);
}
