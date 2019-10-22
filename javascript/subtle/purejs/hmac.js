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

goog.module('tink.subtle.purejs.Hmac');

const Bytes = goog.require('tink.subtle.Bytes');
const GoogHmac = goog.require('goog.crypt.Hmac');
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const Mac = goog.require('tink.Mac');
const Sha1 = goog.require('goog.crypt.Sha1');
const Sha256 = goog.require('goog.crypt.Sha256');
const Sha512 = goog.require('goog.crypt.Sha512');
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
   * @param {string} hash name of the hash function, accepted names are SHA-1,
   *     SHA-256 and SHA-512
   * @param {!Uint8Array} key
   * @param {number} tagSize the size of the tag
   */
  constructor(hash, key, tagSize) {
    /** @const @private {number} */
    this.tagSize_ = tagSize;

    /** @private {!GoogHmac} */
    this.hmac_;

    switch (hash) {
      case 'SHA-1':
        this.hmac_ = new GoogHmac(new Sha1(), Array.from(key));
        break;
      case 'SHA-256':
        this.hmac_ = new GoogHmac(new Sha256(), Array.from(key));
        break;
      case 'SHA-512':
        this.hmac_ = new GoogHmac(new Sha512(), Array.from(key));
        break;
      default:
        throw new InvalidArgumentsException(hash + ' is not supported');
    }
  }

  /**
   * @override
   */
  async computeMac(data) {
    Validators.requireUint8Array(data);
    const tag = this.hmac_.getHmac(data);
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
