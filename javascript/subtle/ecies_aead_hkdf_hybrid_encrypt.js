// Licensed under the Apache License, Version 2.0 (the "License");
//
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

goog.module('tink.subtle.EciesAeadHkdfHybridEncrypt');

const Bytes = goog.require('tink.subtle.Bytes');
const EciesAeadHkdfDemHelper = goog.require('tink.subtle.EciesAeadHkdfDemHelper');
const EciesHkdfKemSender = goog.require('tink.subtle.EciesHkdfKemSender');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const {HybridEncrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_encrypt');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');

/**
 * Implementation of ECIES AEAD HKDF hybrid encryption.
 *
 * @protected
 * @final
 */
class EciesAeadHkdfHybridEncrypt extends HybridEncrypt {
  /**
   * @param {!EciesHkdfKemSender} kemSender
   * @param {string} hkdfHash the name of the HMAC algorithm, accepted names
   *     are: SHA-1, SHA-256 and SHA-512.
   * @param {!EllipticCurves.PointFormatType} pointFormat
   * @param {!EciesAeadHkdfDemHelper} demHelper
   * @param {!Uint8Array=} opt_hkdfSalt
   */
  constructor(kemSender, hkdfHash, pointFormat, demHelper, opt_hkdfSalt) {
    super();

    // TODO(thaidn): do we actually need these null checks?
    if (!kemSender) {
      throw new SecurityException('KEM sender has to be non-null.');
    }
    if (!hkdfHash) {
      throw new SecurityException('HMAC algorithm has to be non-null.');
    }
    if (!pointFormat) {
      throw new SecurityException('Point format has to be non-null.');
    }
    if (!demHelper) {
      throw new SecurityException('DEM helper has to be non-null.');
    }

    /** @private @const {!EciesHkdfKemSender} */
    this.kemSender_ = kemSender;
    /** @private @const {string} */
    this.hkdfHash_ = hkdfHash;
    /** @private @const {!EllipticCurves.PointFormatType} */
    this.pointFormat_ = pointFormat;
    /** @private @const {!EciesAeadHkdfDemHelper} */
    this.demHelper_ = demHelper;
    /** @private @const {!Uint8Array|undefined} */
    this.hkdfSalt_ = opt_hkdfSalt;
  }

  /**
   * @param {!webCrypto.JsonWebKey} recipientPublicKey
   * @param {string} hkdfHash the name of the HMAC algorithm, accepted names
   *     are: SHA-1, SHA-256 and SHA-512.
   * @param {!EllipticCurves.PointFormatType} pointFormat
   * @param {!EciesAeadHkdfDemHelper} demHelper
   * @param {!Uint8Array=} opt_hkdfSalt
   *
   * @return {!Promise.<!HybridEncrypt>}
   */
  static async newInstance(
      recipientPublicKey, hkdfHash, pointFormat, demHelper, opt_hkdfSalt) {
    if (!recipientPublicKey) {
      throw new SecurityException('Recipient public key has to be non-null.');
    }
    if (!hkdfHash) {
      throw new SecurityException('HMAC algorithm has to be non-null.');
    }
    if (!pointFormat) {
      throw new SecurityException('Point format has to be non-null.');
    }
    if (!demHelper) {
      throw new SecurityException('DEM helper has to be non-null.');
    }

    const kemSender = await EciesHkdfKemSender.newInstance(recipientPublicKey);
    return new EciesAeadHkdfHybridEncrypt(
        kemSender, hkdfHash, pointFormat, demHelper, opt_hkdfSalt);
  }

  /**
   * Encrypts plaintext using opt_contextInfo as info parameter of the
   * underlying HKDF.
   *
   * @override
   */
  async encrypt(plaintext, opt_contextInfo) {
    // Variable hkdfInfo is not optional for encapsulate method. Thus it
    // should be an empty array in case that it is not defined by caller of this
    // method.
    if (!opt_contextInfo) {
      opt_contextInfo = new Uint8Array(0);
    }

    const keySizeInBytes = this.demHelper_.getDemKeySizeInBytes();
    const kemKey = await this.kemSender_.encapsulate(
        keySizeInBytes, this.pointFormat_, this.hkdfHash_, opt_contextInfo,
        this.hkdfSalt_);
    const aead = await this.demHelper_.getAead(kemKey['key']);

    const ciphertextBody = await aead.encrypt(plaintext);
    const header = kemKey['token'];

    return Bytes.concat(header, ciphertextBody);
  }
}

exports = EciesAeadHkdfHybridEncrypt;
