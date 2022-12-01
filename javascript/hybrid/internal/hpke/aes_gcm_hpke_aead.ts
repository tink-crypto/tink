/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {insecureIvAesGcmFromRawKey, IV_SIZE_IN_BYTES} from '../../../aead/internal/insecure_iv_aes_gcm';
import {SecurityException} from '../../../exception/security_exception';

import {HpkeAead} from './hpke_aead';
import * as hpkeUtil from './hpke_util';

/**
 * AES-GCM HPKE AEAD variant.
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
 */
export class AesGcmHpkeAead implements HpkeAead {
  constructor(private readonly keyLength: 16|32) {}

  async seal({key, nonce, plaintext, associatedData}: {
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array
  }): Promise<Uint8Array> {
    if (key.length !== this.keyLength) {
      throw new SecurityException(
          'Unexpected key length: ' + key.length.toString());
    }
    const aead = await insecureIvAesGcmFromRawKey({key, prependIv: false});
    return await aead.encrypt(nonce, plaintext, associatedData);
  }

  async open({key, nonce, ciphertext, associatedData}: {
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array
  }): Promise<Uint8Array> {
    if (key.length !== this.keyLength) {
      throw new SecurityException(
          'Unexpected key length: ' + key.length.toString());
    }
    const aead = await insecureIvAesGcmFromRawKey({key, prependIv: false});
    return aead.decrypt(nonce, ciphertext, associatedData);
  }

  getAeadId(): Uint8Array {
    switch (this.keyLength) {
      case 16:
        return hpkeUtil.AES_128_GCM_AEAD_ID;
      case 32:
        return hpkeUtil.AES_256_GCM_AEAD_ID;
    }
  }

  getKeyLength(): number {
    return this.keyLength;
  }

  getNonceLength(): number {
    return IV_SIZE_IN_BYTES;
  }
}
