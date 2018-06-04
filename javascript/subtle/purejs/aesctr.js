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

goog.module('tink.subtle.purejs.AesCtr');

const Aes = goog.require('goog.crypt.Aes');
const Bytes = goog.require('tink.subtle.Bytes');
const Ctr = goog.require('goog.crypt.Ctr');
const IndCpaCipher = goog.require('tink.subtle.IndCpaCipher');
const Random = goog.require('tink.subtle.Random');
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
   * @param {!Uint8Array} key
   * @param {number} ivSize the size of the IV
   */
  constructor(key, ivSize) {
    /** @const @private {number} */
    this.ivSize_ = ivSize;

    /** @const @private {Ctr} */
    this.ctr_ = new Ctr(new Aes(Array.from(key)));
  }

  /**
   * @override
   */
  async encrypt(plaintext) {
    const iv = Random.randBytes(this.ivSize_);
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(iv);
    return Bytes.concat(
        iv, new Uint8Array(this.ctr_.encrypt(plaintext, counter)));
  }

  /**
   * @override
   */
  async decrypt(ciphertext) {
    const counter = new Uint8Array(AES_BLOCK_SIZE_IN_BYTES);
    counter.set(array.slice(ciphertext, 0, this.ivSize_));
    return new Uint8Array(
        this.ctr_.decrypt(array.slice(ciphertext, this.ivSize_), counter));
  }
}

exports = AesCtr;
