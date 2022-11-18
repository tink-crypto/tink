/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../../../exception/security_exception';
import {fromRawKey as hmacFromRawKey} from '../../../subtle/hmac';
import * as validators from '../../../subtle/validators';

import {HpkeKdf} from './hpke_kdf';
import * as hpkeUtil from './hpke_util';

/**
 * HKDF HPKE KDF variant.
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1-3
 */
export class HkdfHpkeKdf implements HpkeKdf {
  constructor(private readonly macAlgorithm: 'SHA-256'|'SHA-512') {}

  async labeledExtract({ikm, ikmLabel, suiteId, salt}: {
    ikm: Uint8Array,
    ikmLabel: string,
    suiteId: Uint8Array,
    salt?: Uint8Array
  }): Promise<Uint8Array> {
    return await this.extract(
        hpkeUtil.labelIkm({ikmLabel, ikm, suiteId}), salt);
  }

  async labeledExpand({prk, info, infoLabel, suiteId, length}: {
    prk: Uint8Array,
    info: Uint8Array,
    infoLabel: string,
    suiteId: Uint8Array,
    length: number
  }): Promise<Uint8Array> {
    return await this.expand(
        prk, hpkeUtil.labelInfo({infoLabel, info, suiteId, length}), length);
  }

  async extractAndExpand(
      {ikm, ikmLabel, info, infoLabel, suiteId, length, salt}: {
        ikm: Uint8Array,
        ikmLabel: string,
        info: Uint8Array,
        infoLabel: string,
        suiteId: Uint8Array,
        length: number,
        salt?: Uint8Array
      }): Promise<Uint8Array> {
    const prk: Uint8Array =
        await this.extract(hpkeUtil.labelIkm({ikmLabel, ikm, suiteId}), salt);
    return await this.expand(
        prk, hpkeUtil.labelInfo({infoLabel, info, suiteId, length}), length);
  }

  /**
   * Copied from `javascript/subtle/hkdf`'s `compute` function
   */
  private async expand(prk: Uint8Array, info: Uint8Array, length: number):
      Promise<Uint8Array> {
    if (!Number.isInteger(length)) {
      throw new SecurityException('length must be an integer');
    }
    if (length <= 0) {
      throw new SecurityException('length must be positive');
    }

    const digestSize = this.getMacLength();

    if (length > 255 * digestSize) {
      throw new SecurityException('length too large');
    }
    validators.requireUint8Array(info);

    const hmac = await hmacFromRawKey(this.macAlgorithm, prk, digestSize);
    let ctr = 1;
    let pos = 0;
    let digest = new Uint8Array(0);
    const result = new Uint8Array(length);
    while (true) {
      const input = new Uint8Array(digest.length + info.length + 1);
      input.set(digest, 0);
      input.set(info, digest.length);
      input[input.length - 1] = ctr;
      digest = await hmac.computeMac(input);
      if (pos + digest.length < length) {
        result.set(digest, pos);
        pos += digest.length;
        ctr++;
      } else {
        result.set(digest.subarray(0, length - pos), pos);
        break;
      }
    }
    return result;
  }

  /**
   * Copied from `javascript/subtle/hkdf`'s `compute` function
   */
  private async extract(ikm: Uint8Array, salt?: Uint8Array):
      Promise<Uint8Array> {
    validators.requireUint8Array(ikm);
    const digestSize = this.getMacLength();
    if (!salt?.length) {
      salt = new Uint8Array(digestSize);
    }
    validators.requireUint8Array(salt);

    const hmac = await hmacFromRawKey(this.macAlgorithm, salt, digestSize);
    const prk = await hmac.computeMac(ikm);

    return prk;
  }

  getKdfId(): Uint8Array {
    switch (this.macAlgorithm) {
      case 'SHA-256':
        return hpkeUtil.HKDF_SHA256_KDF_ID;
      case 'SHA-512':
        return hpkeUtil.HKDF_SHA512_KDF_ID;
    }
  }

  getMacLength(): number {
    switch (this.macAlgorithm) {
      case 'SHA-256':
        return 32;
      case 'SHA-512':
        return 64;
    }
  }
}
