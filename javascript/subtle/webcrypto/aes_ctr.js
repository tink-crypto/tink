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

goog.module('tink.subtle.webcrypto.AesCtr');

const Bytes = goog.require('tink.subtle.Bytes');
const IndCpaCipher = goog.require('tink.subtle.IndCpaCipher');
const Random = goog.require('tink.subtle.Random');
const SecurityException = goog.require('tink.exception.SecurityException');
const Validators = goog.require('tink.subtle.Validators');
const array = goog.require('goog.array');

/**
 * AES block size.
 *
 * @const {number}
 */
const AES_BLOCK_SIZE_IN_BYTES = 16;

/**
 * Implementation of AES-CTR.
 *
 * @implements {IndCpaCipher}
 * @protected
 * @final
 */
class AesCtr {
  /**
   * @param {!webCrypto.CryptoKey} key
   * @param {number} ivSize the size of the IV
   */
  constructor(key, ivSize) {
    /** @const @private {!webCrypto.CryptoKey} */
    this.key_ = key;

    /** @const @private {number} */
    this.ivSize_ = ivSize;
  }

   /**
   * @param {!Uint8Array} key
   * @param {number} ivSize the size of the IV
   * @return {!Promise.<!IndCpaCipher>}
   * @static
   */
  static async newInstance(key, ivSize) {
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw', key, {'name': 'AES-CTR', 'length': key.length}, false,
      ['encrypt', 'decrypt']);

    return new AesCtr(cryptoKey, ivSize);
  }

  /**
   * @override
   */
  async encrypt(plaintext) {
    Validators.requireUint8Array(plaintext);
    const iv = Random.randBytes(this.ivSize_);
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(iv);
    const alg = {'name': 'AES-CTR', 'counter': counter, 'length': 128};
    const ciphertext =
        await window.crypto.subtle.encrypt(alg, this.key_, plaintext);
    return Bytes.concat(iv, new Uint8Array(ciphertext));
  }

  /**
   * @override
   */
  async decrypt(ciphertext) {
    Validators.requireUint8Array(ciphertext);
    if (ciphertext.length < this.ivSize_) {
      throw new SecurityException('ciphertext too short');
    }
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(array.slice(ciphertext, 0, this.ivSize_));
    const alg = {'name': 'AES-CTR', 'counter': counter, 'length': 128};
    return new Uint8Array(await window.crypto.subtle.decrypt(
        alg, this.key_, new Uint8Array(array.slice(ciphertext, this.ivSize_))));
  }
}

exports = AesCtr;
