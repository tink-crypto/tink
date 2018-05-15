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

const Aes = goog.require('goog.crypt.Aes');
const Bytes = goog.require('tink.subtle.Bytes');
const Ctr = goog.require('goog.crypt.Ctr');
const IndCpaCipher = goog.require('tink.subtle.IndCpaCipher');
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const Random = goog.require('tink.subtle.Random');
const Validators = goog.require('tink.subtle.Validators');
const array = goog.require('goog.array');

/**
 * The minimize IV size.
 *
 * @const {int}
 */
const MIN_IV_SIZE_IN_BYTES = 12;

/**
 * AES block size.
 *
 * @const {int}
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
   * @param {!Uint8Array} key
   * @param {int} ivSize the size of the IV, must be larger than or equal to
   *     {@link MIN_IV_SIZE_IN_BYTES}
   * @throws {InvalidArgumentsException}
   */
  constructor(key, ivSize) {
    if (ivSize < MIN_IV_SIZE_IN_BYTES || ivSize > AES_BLOCK_SIZE_IN_BYTES) {
      throw new InvalidArgumentsException(
          'invaid IV length, must be at least ' + MIN_IV_SIZE_IN_BYTES +
          ' and at most ' + AES_BLOCK_SIZE_IN_BYTES);
    }
    /** @const @private {int} */
    this.ivSize_ = ivSize;

    Validators.validateAesKeySize(key.length);
    /** @const @private {Ctr} */
    this.ctr_ = new Ctr(new Aes(key));
  }

  /**
   * @override
   */
  encrypt(plaintext) {
    const iv = Random.randBytes(this.ivSize_);
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(iv);
    return Bytes.concat(iv, this.ctr_.encrypt(plaintext, counter));
  }

  /**
   * @override
   */
  decrypt(ciphertext) {
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(array.slice(ciphertext, 0, this.ivSize_));
    return new Uint8Array(
        this.ctr_.decrypt(array.slice(ciphertext, this.ivSize_), counter));
  }
}

exports = AesCtr;
