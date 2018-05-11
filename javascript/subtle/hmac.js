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
const GoogHmac = goog.require('goog.crypt.Hmac');
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const Mac = goog.require('tink.Mac');
const SecurityException = goog.require('tink.exception.SecurityException');
const Sha1 = goog.require('goog.crypt.Sha1');
const Sha256 = goog.require('goog.crypt.Sha256');
const Sha512 = goog.require('goog.crypt.Sha512');
const array = goog.require('goog.array');

/**
 * Implementation of HMAC.
 *
 * @implements {Mac}
 * @public
 * @final
 */
class Hmac {
  /**
   * @param {string} algoName accepted names are HMACSHA1, HMACSHA256 and
   *     HMACSHA512
   * @param {!Uint8Array} key must be longer than
   *     {@link Mac.MIN_KEY_SIZE_IN_BYTES}
   * @param {int} tagSize the size of the tag, must be larger than or equal to
   *     {@link Mac.MIN_TAG_SIZE_IN_BYTES}
   * @throws {InvalidArgumentException}
   */
  constructor(algoName, key, tagSize) {
    /** @const @private {int} */
    this.tagSize_ = tagSize;

    /** @const @private {GoogHmac} */
    this.hmac_;

    if (tagSize < Mac.MIN_TAG_SIZE_IN_BYTES) {
      throw new InvalidArgumentsException(
          'tag too short, must be at least ' + Mac.MIN_TAG_SIZE_IN_BYTES);
    }

    if (key.length < Mac.MIN_KEY_SIZE_IN_BYTES) {
      throw new InvalidArgumentsException(
          'key too short, must be at least ' + Mac.MIN_KEY_SIZE_IN_BYTES);
    }

    switch (algoName) {
      case 'HMACSHA1':
        if (tagSize > 20) {
          throw new InvalidArgumentsException(
              'tag too long, must not be larger than 20');
        }
        this.hmac_ = new GoogHmac(new Sha1(), key);
        break;
      case 'HMACSHA256':
        if (tagSize > 32) {
          throw new InvalidArgumentsException(
              'tag too long, must not be larger than 32');
        }
        this.hmac_ = new GoogHmac(new Sha256(), key);
        break;
      case 'HMACSHA512':
        if (tagSize > 64) {
          throw new InvalidArgumentsException(
              'tag too long, must not be larger than 64');
        }
        this.hmac_ = new GoogHmac(new Sha512(), key);
        break;
      default:
        throw new InvalidArgumentException(algoName + ' is not supported');
    }
  }

  /**
   * @override
   */
  computeMac(data) {
    return new Uint8Array(
        array.slice(this.hmac_.getHmac(data), 0, this.tagSize_));
  }

  /**
   * @override
   */
  verifyMac(tag, data) {
    const computedTag = this.computeMac(data);
    if (!Bytes.compare(tag, computedTag)) {
      throw new SecurityException('invalid tag');
    }
  }
}

exports = Hmac;
