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

const Environment = goog.require('tink.subtle.Environment');
const HmacPureJs = goog.require('tink.subtle.purejs.Hmac');
const HmacWebCrypto = goog.require('tink.subtle.webcrypto.Hmac');
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const Mac = goog.require('tink.Mac');
const Validators = goog.require('tink.subtle.Validators');

/**
 * The minimum tag size.
 *
 * @const {number}
 */
const MIN_TAG_SIZE_IN_BYTES = 10;

/**
 * @param {string} hash accepted names are SHA-1, SHA-256 and SHA-512
 * @param {!Uint8Array} key the HMAC key, should not be shorter than 128 bits.
 * @param {number} tagSize the size of the tag, must be larger than or equal
 *     to {@link MIN_TAG_SIZE_IN_BYTES}
 * @return {!Promise.<!Mac>}
 */
const newInstance = async function(hash, key, tagSize) {
  Validators.requireUint8Array(key);
  if (tagSize < MIN_TAG_SIZE_IN_BYTES) {
    throw new InvalidArgumentsException(
        'tag too short, must be at least ' + MIN_TAG_SIZE_IN_BYTES + ' bytes');
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

  if (Environment.IS_WEBCRYPTO_AVAILABLE) {
    return await HmacWebCrypto.newInstance(hash, key, tagSize);
  }

  return new HmacPureJs(hash, key, tagSize);
};

exports = {newInstance};
