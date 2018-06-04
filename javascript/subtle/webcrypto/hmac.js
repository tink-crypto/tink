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

/**
 * Implementation of HMAC.
 *
 * @implements {Mac}
 * @public
 * @final
 */
class Hmac {
  /**
   * @param {!webCrypto.CryptoKey} key
   * @param {number} tagSize the size of the tag
   */
  constructor(key, tagSize) {
    /** @const @private {number} */
    this.tagSize_ = tagSize;

    /** @const @private {!webCrypto.CryptoKey} */
    this.key_ = key;
  }

  /**
   * @override
   */
  async computeMac(data) {
    const tag =
        await window.crypto.subtle.sign({'name': 'HMAC'}, this.key_, data);
    return new Uint8Array(tag.slice(0, this.tagSize_));
  }

  /**
   * @override
   */
  async verifyMac(tag, data) {
    const computedTag = await this.computeMac(data);
    return Bytes.isEqual(tag, computedTag);
  }
}

exports = Hmac;
