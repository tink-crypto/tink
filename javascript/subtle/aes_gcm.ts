/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Aead} from '../aead/internal/aead';
import {SecurityException} from '../exception/security_exception';

import * as Bytes from './bytes';
import * as Random from './random';
import * as Validators from './validators';

/**
 * The only supported IV size.
 *
 */
const IV_SIZE_IN_BYTES: number = 12;

/**
 * The only supported tag size.
 *
 */
const TAG_SIZE_IN_BITS: number = 128;

/**
 * Implementation of AES-GCM.
 *
 * @final
 */
export class AesGcm extends Aead {
  constructor(private readonly key: CryptoKey) {
    super();
  }

  /**
   */
  async encrypt(plaintext: Uint8Array, associatedData?: Uint8Array):
      Promise<Uint8Array> {
    Validators.requireUint8Array(plaintext);
    if (associatedData != null) {
      Validators.requireUint8Array(associatedData);
    }
    const iv = Random.randBytes(IV_SIZE_IN_BYTES);
    const alg: AesGcmParams = {
      'name': 'AES-GCM',
      'iv': iv,
      'tagLength': TAG_SIZE_IN_BITS
    };
    if (associatedData) {
      alg['additionalData'] = associatedData;
    }
    const ciphertext =
        await self.crypto.subtle.encrypt(alg, this.key, plaintext);
    return Bytes.concat(iv, new Uint8Array(ciphertext));
  }

  /**
   */
  async decrypt(ciphertext: Uint8Array, associatedData?: Uint8Array):
      Promise<Uint8Array> {
    Validators.requireUint8Array(ciphertext);
    if (ciphertext.length < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BITS / 8) {
      throw new SecurityException('ciphertext too short');
    }
    if (associatedData != null) {
      Validators.requireUint8Array(associatedData);
    }
    const iv = new Uint8Array(IV_SIZE_IN_BYTES);
    iv.set(ciphertext.subarray(0, IV_SIZE_IN_BYTES));
    const alg: AesGcmParams = {
      'name': 'AES-GCM',
      'iv': iv,
      'tagLength': TAG_SIZE_IN_BITS
    };
    if (associatedData) {
      alg['additionalData'] = associatedData;
    }
    try {
      return new Uint8Array(await self.crypto.subtle.decrypt(
          alg, this.key,
          new Uint8Array(ciphertext.subarray(IV_SIZE_IN_BYTES))));
    } catch (e) {
      throw new SecurityException(e.toString());
    }
  }
}

export async function fromRawKey(key: Uint8Array): Promise<Aead> {
  Validators.requireUint8Array(key);
  Validators.validateAesKeySize(key.length);
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
