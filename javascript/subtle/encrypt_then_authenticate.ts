/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Aead} from '../aead/internal/aead';
import {SecurityException} from '../exception/security_exception';
import {Mac} from '../mac/internal/mac';

import * as aesCtr from './aes_ctr';
import * as Bytes from './bytes';
import * as hmac from './hmac';
import {IndCpaCipher} from './ind_cpa_cipher';
import * as Validators from './validators';

/**
 * This primitive performs an encrypt-then-Mac operation on plaintext and
 * additional authenticated data (aad).
 *
 * The Mac is computed over `aad || ciphertext || size of aad`, thus it
 * doesn't violate https://en.wikipedia.org/wiki/Horton_Principle.
 *
 * This implementation is based on
 * http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.
 *
 * @final
 */
export class EncryptThenAuthenticate extends Aead {
  /**
   * @param ivSize the IV size in bytes
   * @param tagSize the MAC tag size in bytes
   * @throws {InvalidArgumentsException}
   */
  constructor(
      private readonly cipher: IndCpaCipher, private readonly ivSize: number,
      private readonly mac: Mac, private readonly tagSize: number) {
    super();
  }

  /**
   * The plaintext is encrypted with an {@link IndCpaCipher}, then MAC
   * is computed over `aad || ciphertext || t` where t is aad's length in bits
   * represented as 64-bit bigendian unsigned integer. The final ciphertext
   * format is `ind-cpa ciphertext || mac`.
   *
   */
  async encrypt(plaintext: Uint8Array, associatedData = new Uint8Array(0)):
      Promise<Uint8Array> {
    Validators.requireUint8Array(plaintext);
    const payload = await this.cipher.encrypt(plaintext);
    Validators.requireUint8Array(associatedData);
    const aadLength = Bytes.fromNumber(associatedData.length * 8);
    const mac = await this.mac.computeMac(
        Bytes.concat(associatedData, payload, aadLength));
    if (this.tagSize != mac.length) {
      throw new SecurityException(
          'invalid tag size, expected ' + this.tagSize + ' but got ' +
          mac.length);
    }
    return Bytes.concat(payload, mac);
  }

  /**
   */
  async decrypt(ciphertext: Uint8Array, associatedData = new Uint8Array(0)):
      Promise<Uint8Array> {
    Validators.requireUint8Array(ciphertext);
    if (ciphertext.length < this.ivSize + this.tagSize) {
      throw new SecurityException('ciphertext too short');
    }
    const payload = new Uint8Array(
        ciphertext.subarray(0, ciphertext.length - this.tagSize));
    Validators.requireUint8Array(associatedData);
    const aadLength = Bytes.fromNumber(associatedData.length * 8);
    const input = Bytes.concat(associatedData, payload, aadLength);
    const tag = new Uint8Array(ciphertext.subarray(payload.length));
    const isValidMac = await this.mac.verifyMac(tag, input);
    if (!isValidMac) {
      throw new SecurityException('invalid MAC');
    }
    return this.cipher.decrypt(payload);
  }
}

/**
 * @param ivSize the size of the IV
 * @param hmacHashAlgo accepted names are SHA-1, SHA-256 and SHA-512
 * @param tagSize the size of the tag
 * @throws {InvalidArgumentsException}
 * @static
 */
export async function aesCtrHmacFromRawKeys(
    aesKey: Uint8Array, ivSize: number, hmacHashAlgo: string,
    hmacKey: Uint8Array, tagSize: number): Promise<EncryptThenAuthenticate> {
  Validators.requireUint8Array(aesKey);
  Validators.requireUint8Array(hmacKey);
  const cipher = await aesCtr.fromRawKey(aesKey, ivSize);
  const mac = await hmac.fromRawKey(hmacHashAlgo, hmacKey, tagSize);
  return new EncryptThenAuthenticate(cipher, ivSize, mac, tagSize);
}
