// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.subtle.AesGcm');

const Aead = goog.require('tink.Aead');
const Bytes = goog.require('tink.subtle.Bytes');
const Random = goog.require('tink.subtle.Random');
const SecurityException = goog.require('tink.exception.SecurityException');
const Validators = goog.require('tink.subtle.Validators');

/**
 * The only supported IV size.
 *
 * @const {number}
 */
const IV_SIZE_IN_BYTES = 12;

/**
 * The only supported tag size.
 *
 * @const {number}
 */
const TAG_SIZE_IN_BITS = 128;

/**
 * Implementation of AES-GCM.
 *
 * @implements {Aead}
 * @public
 * @final
 */
class AesGcm {
  /**
   * @param {!webCrypto.CryptoKey} key
   */
  constructor(key) {
    /** @const @private {!webCrypto.CryptoKey} */
    this.key_ = key;
  }

  /**
   * @param {!Uint8Array} key
   * @return {!Promise.<!Aead>}
   * @static
   */
  static async newInstance(key) {
    Validators.requireUint8Array(key);
    Validators.validateAesKeySize(key.length);

    const webCryptoKey = await self.crypto.subtle.importKey(
        'raw' /* format */, key /* keyData */,
        {'name': 'AES-GCM', 'length': key.length} /* algo */,
        false /* extractable*/, ['encrypt', 'decrypt'] /* usage */);
    return new AesGcm(webCryptoKey);
  }

  /**
   * @override
   */
  async encrypt(plaintext, opt_associatedData) {
    Validators.requireUint8Array(plaintext);
    if (goog.isDefAndNotNull(opt_associatedData)) {
      Validators.requireUint8Array(opt_associatedData);
    }
    const iv = Random.randBytes(IV_SIZE_IN_BYTES);
    const alg = {
      'name': 'AES-GCM',
      'iv': iv,
      'tagLength': TAG_SIZE_IN_BITS,
    };
    // Edge can't handle an empty array
    if (goog.isDefAndNotNull(opt_associatedData) && opt_associatedData.length) {
      alg['additionalData'] = opt_associatedData;
    }
    const ciphertext =
        await self.crypto.subtle.encrypt(alg, this.key_, plaintext);
    return Bytes.concat(iv, new Uint8Array(ciphertext));
  }

  /**
   * @override
   */
  async decrypt(ciphertext, opt_associatedData) {
    Validators.requireUint8Array(ciphertext);
    if (ciphertext.length < IV_SIZE_IN_BYTES + TAG_SIZE_IN_BITS / 8) {
      throw new SecurityException('ciphertext too short');
    }
    if (goog.isDefAndNotNull(opt_associatedData)) {
      Validators.requireUint8Array(opt_associatedData);
    }
    const iv = new Uint8Array(IV_SIZE_IN_BYTES);
    iv.set(ciphertext.subarray(0, IV_SIZE_IN_BYTES));
    const alg = {
      'name': 'AES-GCM',
      'iv': iv,
      'tagLength': TAG_SIZE_IN_BITS,
    };
    // Edge can't handle an empty array
    if (goog.isDefAndNotNull(opt_associatedData) && opt_associatedData.length) {
      alg['additionalData'] = opt_associatedData;
    }
    try {
      return new Uint8Array(await self.crypto.subtle.decrypt(
          alg, this.key_,
          new Uint8Array(ciphertext.subarray(IV_SIZE_IN_BYTES))));
    } catch (e) {
      throw new SecurityException(e.toString());
    }
  }
}

exports = AesGcm;
