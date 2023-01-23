/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../exception/invalid_arguments_exception';
import {SecurityException} from '../../exception/security_exception';

import * as bytes from '../../subtle/bytes';

/**
 * The only supported IV size.
 *
 */
export const IV_SIZE_IN_BYTES: number = 12;

/**
 * The only supported tag size.
 *
 */
const TAG_SIZE_IN_BYTES: number = 16;

/**
 * Insecure version of `subtle/aes_gcm.ts` that allows the caller to set
 * the IV.
 *
 * @final
 */
export class InsecureIvAesGcm {
  private readonly key: CryptoKey;
  private readonly prependIv: boolean;
  constructor({key, prependIv}:
                  {readonly key: CryptoKey, readonly prependIv: boolean}) {
    this.key = key;
    this.prependIv = prependIv;
  }

  async encrypt(
      iv: Uint8Array, plaintext: Uint8Array,
      associatedData?: Uint8Array): Promise<Uint8Array> {
    if (iv.length !== IV_SIZE_IN_BYTES) {
      throw new SecurityException(`IV must be ${IV_SIZE_IN_BYTES} bytes`);
    }

    const alg: AesGcmParams = {
      'name': 'AES-GCM',
      'iv': iv,
      'tagLength': TAG_SIZE_IN_BYTES * 8
    };
    if (associatedData) {
      alg.additionalData = associatedData;
    }
    const ciphertext =
        await self.crypto.subtle.encrypt(alg, this.key, plaintext);

    return (
        this.prependIv ? bytes.concat(iv, new Uint8Array(ciphertext)) :
                         new Uint8Array(ciphertext));
  }

  async decrypt(
      iv: Uint8Array, ciphertext: Uint8Array,
      associatedData?: Uint8Array): Promise<Uint8Array> {
    const expectedLength = this.prependIv ?
        IV_SIZE_IN_BYTES + TAG_SIZE_IN_BYTES :
        TAG_SIZE_IN_BYTES;

    if (ciphertext.length < expectedLength) {
      throw new SecurityException('ciphertext too short');
    }

    if (iv.length !== IV_SIZE_IN_BYTES) {
      throw new SecurityException(`IV must be ${IV_SIZE_IN_BYTES} bytes`);
    }

    const alg: AesGcmParams = {
      'name': 'AES-GCM',
      'iv': iv,
      'tagLength': TAG_SIZE_IN_BYTES * 8
    };
    if (associatedData) {
      alg.additionalData = associatedData;
    }
    const ciphertextWithoutIv = this.prependIv ?
        new Uint8Array(ciphertext.subarray(IV_SIZE_IN_BYTES)) :
        ciphertext;

    try {
      return new Uint8Array(
          await self.crypto.subtle.decrypt(alg, this.key, ciphertextWithoutIv));
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      throw new SecurityException(e.toString());
    }
  }
}

/**
 * Returns an instantiated `InsecureIvAesGcm` given a raw byte array `key`
 * and `prependIv` flag.
 */
export async function insecureIvAesGcmFromRawKey(
    {key, prependIv}: {key: Uint8Array, prependIv: boolean}):
    Promise<InsecureIvAesGcm> {
  validateAesKeySize(key.length);
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
  return new InsecureIvAesGcm({key: webCryptoKey, prependIv});
}

/**
 * Validates AES key sizes (only 128-bit and 256-bit keys are supported).
 *
 * @param n the key size in bytes
 * @throws {!InvalidArgumentsException}
 *
 * Copied from `javascript/subtle/validators`
 * TODO(b/201071402#comment8): Delete once circular dependency is resolved
 */
function validateAesKeySize(n: number) {
  if (![16, 32].includes(n)) {
    throw new InvalidArgumentsException('unsupported AES key size: ${n}');
  }
}
