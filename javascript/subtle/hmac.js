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

goog.module('tink.subtle.Hmac');

const Bytes = goog.require('tink.subtle.Bytes');
const {InvalidArgumentsException} = goog.require('google3.third_party.tink.javascript.exception.invalid_arguments_exception');
const {Mac} = goog.require('google3.third_party.tink.javascript.mac.internal.mac');
const Validators = goog.require('tink.subtle.Validators');

/**
 * The minimum tag size.
 *
 * @const {number}
 */
const MIN_TAG_SIZE_IN_BYTES = 10;

/**
 * Implementation of HMAC.
 *
 * @public
 * @final
 */
class Hmac extends Mac {
  /**
   * @param {string} hash accepted names are SHA-1, SHA-256 and SHA-512
   * @param {!webCrypto.CryptoKey} key
   * @param {number} tagSize the size of the tag
   */
  constructor(hash, key, tagSize) {
    super();

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
    Validators.requireUint8Array(key);
    if (!Number.isInteger(tagSize)) {
      throw new InvalidArgumentsException(
          'invalid tag size, must be an integer');
    }
    if (tagSize < MIN_TAG_SIZE_IN_BYTES) {
      throw new InvalidArgumentsException(
          'tag too short, must be at least ' + MIN_TAG_SIZE_IN_BYTES +
          ' bytes');
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
