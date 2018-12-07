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

goog.module('tink.subtle.webcrypto.Hmac');

const Bytes = goog.require('tink.subtle.Bytes');
const Mac = goog.require('tink.Mac');
const Validators = goog.require('tink.subtle.Validators');

/**
 * Implementation of HMAC.
 *
 * @implements {Mac}
 * @public
 * @final
 */
class Hmac {
  /**
   * @param {string} hash accepted names are SHA-1, SHA-256 and SHA-512
   * @param {!webCrypto.CryptoKey} key
   * @param {number} tagSize the size of the tag
   */
  constructor(hash, key, tagSize) {
    /** @const @private {string} */
    this.hash_ = hash;

    /** @const @private {number} */
    this.tagSize_ = tagSize;

    /** @const @private {!webCrypto.CryptoKey} */
    this.key_ = key;
  }

   /**
   * @param {string} hash accepted names are SHA-1, SHA-256 and SHA-512
   * @param {!Uint8Array} key
   * @param {number} tagSize the size of the tag
   * @return {!Promise.<!Mac>}
   * @static
   */
  static async newInstance(hash, key, tagSize) {
    let cryptoKey = await self.crypto.subtle.importKey(
      'raw', key,
      {'name': 'HMAC', 'hash': {'name': hash}, 'length': key.length * 8},
      false, ['sign', 'verify']);

    return new Hmac(hash, cryptoKey, tagSize);
  }

  /**
   * @override
   */
  async computeMac(data) {
    Validators.requireUint8Array(data);
    const tag = await self.crypto.subtle.sign(
        {'name': 'HMAC', 'hash': {'name': this.hash_}}, this.key_, data);
    return new Uint8Array(tag.slice(0, this.tagSize_));
  }

  /**
   * @override
   */
  async verifyMac(tag, data) {
    Validators.requireUint8Array(tag);
    Validators.requireUint8Array(data);
    const computedTag = await this.computeMac(data);
    return Bytes.isEqual(tag, computedTag);
  }
}

exports = Hmac;
