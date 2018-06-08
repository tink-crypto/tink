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

const AesCtrPureJs = goog.require('tink.subtle.purejs.AesCtr');
const AesCtrWebCrypto = goog.require('tink.subtle.webcrypto.AesCtr');
const Environment = goog.require('tink.subtle.Environment');
const IndCpaCipher = goog.require('tink.subtle.IndCpaCipher');
const SecurityException = goog.require('tink.exception.SecurityException');
const Validators = goog.require('tink.subtle.Validators');

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
 * @param {!Uint8Array} key
 * @param {number} ivSize the size of the IV, must be larger than or equal to
 *     {@link MIN_IV_SIZE_IN_BYTES}
 * @return {!Promise.<!IndCpaCipher>}
 * @static
 */
const create = async function(key, ivSize) {
  if (ivSize < MIN_IV_SIZE_IN_BYTES || ivSize > AES_BLOCK_SIZE_IN_BYTES) {
    throw new SecurityException(
        'invaid IV length, must be at least ' + MIN_IV_SIZE_IN_BYTES +
        ' and at most ' + AES_BLOCK_SIZE_IN_BYTES);
  }
  Validators.validateAesKeySize(key.length);

  if (Environment.IS_WEBCRYPTO_AVAILABLE) {
    try {
      const cryptoKey = await window.crypto.subtle.importKey(
          'raw', key, {'name': 'AES-CTR', 'length': key.length}, false,
          ['encrypt', 'decrypt']);
      return new AesCtrWebCrypto(cryptoKey, ivSize);
    } catch (error) {
      // CTR might be unsupported in this browser. Fall back to Pure JS.
    }
  }
  return new AesCtrPureJs(key, ivSize);
};

exports = {create};
