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

goog.module('tink.subtle.EciesAeadHkdfHybridDecrypt');

const {Aead} = goog.require('google3.third_party.tink.javascript.aead.internal.aead');
const EciesAeadHkdfDemHelper = goog.require('tink.subtle.EciesAeadHkdfDemHelper');
const EciesHkdfKemRecipient = goog.require('tink.subtle.EciesHkdfKemRecipient');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const {HybridDecrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_decrypt');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');

/**
 * Implementation of ECIES AEAD HKDF hybrid decryption.
 *
 * @protected
 * @final
 */
class EciesAeadHkdfHybridDecrypt extends HybridDecrypt {
  /**
   * @param {!webCrypto.JsonWebKey} recipientPrivateKey
   * @param {!EciesHkdfKemRecipient} kemRecipient
   * @param {string} hkdfHash the name of the HMAC algorithm, accepted names
   *     are: SHA-1, SHA-256 and SHA-512.
   * @param {!EllipticCurves.PointFormatType} pointFormat
   * @param {!EciesAeadHkdfDemHelper} demHelper
   * @param {!Uint8Array=} opt_hkdfSalt
   */
  constructor(
      recipientPrivateKey, kemRecipient, hkdfHash, pointFormat, demHelper,
      opt_hkdfSalt) {
    super();

    if (!recipientPrivateKey) {
      throw new SecurityException('Recipient private key has to be non-null.');
    }
    if (!kemRecipient) {
      throw new SecurityException('KEM recipient has to be non-null.');
    }
    if (!hkdfHash) {
      throw new SecurityException('HKDF hash algorithm has to be non-null.');
    }
    if (!pointFormat) {
      throw new SecurityException('Point format has to be non-null.');
    }
    if (!demHelper) {
      throw new SecurityException('DEM helper has to be non-null.');
    }

    const curveType =
        EllipticCurves.curveFromString(recipientPrivateKey['crv']);
    const headerSize =
        EllipticCurves.encodingSizeInBytes(curveType, pointFormat);

    /** @private @const {!EciesHkdfKemRecipient} */
    this.kemRecipient_ = kemRecipient;
    /** @private @const {string} */
    this.hkdfHash_ = hkdfHash;
    /** @private @const {!EllipticCurves.PointFormatType} */
    this.pointFormat_ = pointFormat;
    /** @private @const {!EciesAeadHkdfDemHelper} */
    this.demHelper_ = demHelper;
    /** @private @const {number} */
    this.headerSize_ = headerSize;
    /** @private @const {!Uint8Array|undefined} */
    this.hkdfSalt_ = opt_hkdfSalt;
  }

  /**
   * @param {!webCrypto.JsonWebKey} recipientPrivateKey
   * @param {string} hkdfHash the name of the HMAC algorithm, accepted names
   *     are: SHA-1, SHA-256 and SHA-512.
   * @param {!EllipticCurves.PointFormatType} pointFormat
   * @param {!EciesAeadHkdfDemHelper} demHelper
   * @param {!Uint8Array=} opt_hkdfSalt
   *
   * @return {!Promise.<!HybridDecrypt>}
   */
  static async newInstance(
      recipientPrivateKey, hkdfHash, pointFormat, demHelper, opt_hkdfSalt) {
    if (!recipientPrivateKey) {
      throw new SecurityException('Recipient private key has to be non-null.');
    }
    if (!hkdfHash) {
      throw new SecurityException('HKDF hash algorithm has to be non-null.');
    }
    if (!pointFormat) {
      throw new SecurityException('Point format has to be non-null.');
    }
    if (!demHelper) {
      throw new SecurityException('DEM helper has to be non-null.');
    }

    if (!recipientPrivateKey) {
      throw new SecurityException('Recipient private key has to be non-null.');
    }
    const kemRecipient =
        await EciesHkdfKemRecipient.newInstance(recipientPrivateKey);

    return new EciesAeadHkdfHybridDecrypt(
        recipientPrivateKey, kemRecipient, hkdfHash, pointFormat, demHelper,
        opt_hkdfSalt);
  }

  /**
   * Decrypts ciphertext using opt_contextInfo as info parameter of the
   * underlying HKDF.
   *
   * @override
   */
  async decrypt(ciphertext, opt_contextInfo) {
    if (ciphertext.length < this.headerSize_) {
      throw new SecurityException('Ciphertext is too short.');
    }

    // Split the ciphertext to KEM token and AEAD ciphertext.
    const kemToken = ciphertext.slice(0, this.headerSize_);
    const ciphertextBody =
        ciphertext.slice(this.headerSize_, ciphertext.length);

    const aead = await this.getAead_(kemToken, opt_contextInfo);
    return await aead.decrypt(ciphertextBody);
  }

  /**
   * @private
   * @param {!Uint8Array} kemToken
   * @param {?Uint8Array=} opt_contextInfo
   * @return {!Promise<!Aead>}
   */
  async getAead_(kemToken, opt_contextInfo) {
    // Variable hkdfInfo is not optional for decapsulate method. Thus it should
    // be an empty array in case that it is not defined by the caller of decrypt
    // method.
    if (!opt_contextInfo) {
      opt_contextInfo = new Uint8Array(0);
    }

    const symmetricKey = await this.kemRecipient_.decapsulate(
        kemToken, this.demHelper_.getDemKeySizeInBytes(), this.pointFormat_,
        this.hkdfHash_, opt_contextInfo, this.hkdfSalt_);
    return await this.demHelper_.getAead(symmetricKey);
  }
}

exports = EciesAeadHkdfHybridDecrypt;
