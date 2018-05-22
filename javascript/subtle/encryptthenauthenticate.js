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

goog.module('tink.subtle.EncryptThenAuthenticate');

const Aead = goog.require('tink.Aead');
const Bytes = goog.require('tink.subtle.Bytes');
const IndCpaCipher = goog.require('tink.subtle.IndCpaCipher');
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const Mac = goog.require('tink.Mac');
const SecurityException = goog.require('tink.exception.SecurityException');
const array = goog.require('goog.array');

/**
 * This primitive performs an encrypt-then-Mac operation on plaintext and
 * additional authenticated data (aad).
 *
 * The Mac is computed over `aad || ciphertext || size of aad`, thus it
 * doesn't violate https://en.wikipedia.org/wiki/Horton_Principle.
 *
 * This implementation is based on
 * http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.
 *
 * @implements {Aead}
 * @public
 * @final
 */
class EncryptThenAuthenticate {
  /**
   * @param {!IndCpaCipher} cipher
   * @param {!Mac} mac
   * @param {number} tagSize the MAC tag size
   * @throws {InvalidArgumentsException}
   */
  constructor(cipher, mac, tagSize) {
    /** @const @private {IndCpaCipher} */
    this.cipher_ = cipher;

    /** @const @private {Mac} */
    this.mac_ = mac;

    /** @const @private {number} */
    this.tagSize_ = tagSize;
  }

  /**
   * The plaintext is encrypted with an {@link IndCpaCipher}, then MAC
   * is computed over `aad || ciphertext || t` where t is aad's length in bits
   * represented as 64-bit bigendian unsigned integer. The final ciphertext
   * format is `ind-cpa ciphertext || mac`.
   *
   * @override
   */
  encrypt(plaintext, opt_associatedData) {
    const payload = this.cipher_.encrypt(plaintext);
    let aad = new Uint8Array(0);
    if (goog.isDefAndNotNull(opt_associatedData)) {
      aad = opt_associatedData;
    }
    const aadLength = Bytes.fromNumber(aad.length * 8);
    const mac = this.mac_.computeMac(Bytes.concat(aad, payload, aadLength));
    if (this.tagSize_ != mac.length) {
      throw new SecurityException(
          'invalid tag size, expected ' + this.tagSize_ + ' but got ' +
          mac.length);
    }
    return Bytes.concat(payload, mac);
  }

  /**
   * @override
   */
  decrypt(ciphertext, opt_associatedData) {
    if (ciphertext.length < this.tagSize_) {
      throw new SecurityException('ciphertext too short');
    }
    const payload = new Uint8Array(
        array.slice(ciphertext, 0, ciphertext.length - this.tagSize_));
    const providedMac = new Uint8Array(array.slice(ciphertext, payload.length));
    let aad = new Uint8Array(0);
    if (goog.isDefAndNotNull(opt_associatedData)) {
      aad = opt_associatedData;
    }
    const aadLength = Bytes.fromNumber(aad.length * 8);
    const input = Bytes.concat(aad, payload, aadLength);
    const expectedMac = this.mac_.computeMac(input);
    if (!Bytes.isEqual(expectedMac, providedMac)) {
      throw new SecurityException('invalid MAC');
    }
    return this.cipher_.decrypt(payload);
  }
}

exports = EncryptThenAuthenticate;
