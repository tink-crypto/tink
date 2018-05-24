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

goog.module('tink.subtle.AesCtr');

const Bytes = goog.require('tink.subtle.Bytes');
const IndCpaCipher = goog.require('tink.subtle.IndCpaCipher');
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const Random = goog.require('tink.subtle.Random');
const Validators = goog.require('tink.subtle.Validators');
const array = goog.require('goog.array');

/**
 * The minimum IV size.
 *
 * @const {number}
 */
const MIN_IV_SIZE_IN_BYTES = 12;

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
   * @param {number} ivSize the size of the IV, must be larger than or equal to
   *     {@link MIN_IV_SIZE_IN_BYTES}
   */
  constructor(key, ivSize) {
    /** @const @private {!webCrypto.CryptoKey} */
    this.key_ = key;

    /** @const @private {number} */
    this.ivSize_ = ivSize;
  }

  /**
   * @param {!Uint8Array} key
   * @param {number} ivSize the size of the IV, must be larger than or equal to
   *     {@link MIN_IV_SIZE_IN_BYTES}
   * @return {!Promise.<!AesCtr>}
   * @throws {InvalidArgumentsException}
   * @static
   */
  static async new(key, ivSize) {
    if (ivSize < MIN_IV_SIZE_IN_BYTES || ivSize > AES_BLOCK_SIZE_IN_BYTES) {
      throw new InvalidArgumentsException(
          'invaid IV length, must be at least ' + MIN_IV_SIZE_IN_BYTES +
          ' and at most ' + AES_BLOCK_SIZE_IN_BYTES);
    }
    Validators.validateAesKeySize(key.length);

    const cryptoKey = await window.crypto.subtle.importKey(
        'raw', key, {'name': 'AES-CTR', 'length': key.length}, false,
        ['encrypt', 'decrypt']);
    return new AesCtr(cryptoKey, ivSize);
  }

  /**
   * @override
   */
  async encrypt(plaintext) {
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
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(array.slice(ciphertext, 0, this.ivSize_));
    const alg = {'name': 'AES-CTR', 'counter': counter, 'length': 128};
    return new Uint8Array(await window.crypto.subtle.decrypt(
        alg, this.key_, new Uint8Array(array.slice(ciphertext, this.ivSize_))));
  }
}

exports = AesCtr;
