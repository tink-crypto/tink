/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../exception/invalid_arguments_exception';
import {Mac} from '../mac/internal/mac';

import * as Bytes from './bytes';
import * as Validators from './validators';

/**
 * The minimum tag size.
 *
 */
const MIN_TAG_SIZE_IN_BYTES: number = 10;

/**
 * Implementation of HMAC.
 *
 * @final
 */
export class Hmac extends Mac {
  /**
   * @param hash accepted names are SHA-1, SHA-256 and SHA-512
   * @param tagSize the size of the tag
   */
  constructor(
      private readonly hash: string, private readonly key: CryptoKey,
      private readonly tagSize: number) {
    super();
  }

  /**
   */
  async computeMac(data: Uint8Array): Promise<Uint8Array> {
    Validators.requireUint8Array(data);
    const tag = await self.crypto.subtle.sign(
        {'name': 'HMAC', 'hash': {'name': this.hash}}, this.key, data);
    return new Uint8Array(tag.slice(0, this.tagSize));
  }

  /**
   */
  async verifyMac(tag: Uint8Array, data: Uint8Array): Promise<boolean> {
    Validators.requireUint8Array(tag);
    Validators.requireUint8Array(data);
    const computedTag = await this.computeMac(data);
    return Bytes.isEqual(tag, computedTag);
  }
}

/**
 * @param hash accepted names are SHA-1, SHA-256 and SHA-512
 * @param tagSize the size of the tag
 */
export async function fromRawKey(
    hash: string, key: Uint8Array, tagSize: number): Promise<Mac> {
  Validators.requireUint8Array(key);
  if (!Number.isInteger(tagSize)) {
    throw new InvalidArgumentsException('invalid tag size, must be an integer');
  }
  if (tagSize < MIN_TAG_SIZE_IN_BYTES) {
    throw new InvalidArgumentsException(
        'tag too short, must be at least ' + MIN_TAG_SIZE_IN_BYTES + ' bytes');
  }
  switch (hash) {
    case 'SHA-1':
      if (tagSize > 20) {
        throw new InvalidArgumentsException(
            'tag too long, must not be larger than 20 bytes');
      }
      break;
    case 'SHA-256':
      if (tagSize > 32) {
        throw new InvalidArgumentsException(
            'tag too long, must not be larger than 32 bytes');
      }
      break;
    case 'SHA-512':
      if (tagSize > 64) {
        throw new InvalidArgumentsException(
            'tag too long, must not be larger than 64 bytes');
      }
      break;
    default:
      throw new InvalidArgumentsException(hash + ' is not supported');
  }

  // TODO(b/115974209): Add check that key.length > 16.
  const cryptoKey = await self.crypto.subtle.importKey(
      'raw', key,
      {'name': 'HMAC', 'hash': {'name': hash}, 'length': key.length * 8}, false,
      ['sign', 'verify']);
  return new Hmac(hash, cryptoKey, tagSize);
}
