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

goog.module('tink.subtle.EciesHkdfKemSender');

const Bytes = goog.require('tink.subtle.Bytes');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Hkdf = goog.require('tink.subtle.Hkdf');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');

/**
 * HKDF-based ECIES-KEM (key encapsulation mechanism) for ECIES sender.
 */
class EciesHkdfKemSender {
  /**
   * @param {!webCrypto.CryptoKey} recipientPublicKey
   */
  constructor(recipientPublicKey) {
    if (!recipientPublicKey) {
      throw new SecurityException('Recipient public key has to be non-null.');
    }
    // CryptoKey should have the properties type and algorithm.
    if (recipientPublicKey.type !== 'public' || !recipientPublicKey.algorithm) {
      throw new SecurityException('Expected Crypto key of type: public.');
    }
    /** @const @private {!webCrypto.CryptoKey} */
    this.publicKey_ = recipientPublicKey;
  }

  /**
   * @param {!webCrypto.JsonWebKey} jwk
   * @return {!Promise.<!EciesHkdfKemSender>}
   * @static
   */
  static async newInstance(jwk) {
    const publicKey = await EllipticCurves.importPublicKey('ECDH', jwk);
    return new EciesHkdfKemSender(publicKey);
  }

  /**
   * @param {number} keySizeInBytes The length of the generated pseudorandom
   *     string in bytes. The maximal size is 255 * DigestSize, where DigestSize
   *     is the size of the underlying HMAC.
   * @param {!EllipticCurves.PointFormatType} pointFormat The format of the
   *     public ephemeral point.
   * @param {string} hkdfHash the name of the hash function. Accepted names are
   *     SHA-1, SHA-256 and SHA-512.
   * @param {!Uint8Array} hkdfInfo Context and application specific
   *     information (can be a zero-length array).
   * @param {!Uint8Array=} opt_hkdfSalt Salt value (a non-secret random
   *     value). If not provided, it is set to a string of hash length zeros.
   * @return {!Promise.<{key:!Uint8Array, token:!Uint8Array}>} The KEM key and
   *     token.
   */
  async encapsulate(
      keySizeInBytes, pointFormat, hkdfHash, hkdfInfo, opt_hkdfSalt) {
    const ephemeralKeyPair = await EllipticCurves.generateKeyPair(
        'ECDH', this.publicKey_.algorithm['namedCurve']);
    const sharedSecret = await EllipticCurves.computeEcdhSharedSecret(
        /** @type {?} */ (ephemeralKeyPair).privateKey, this.publicKey_);
    const jwk = await EllipticCurves.exportCryptoKey(
        /** @type {?} */ (ephemeralKeyPair).publicKey);
    const kemToken = EllipticCurves.pointEncode(jwk.crv, pointFormat, jwk);
    const hkdfIkm = Bytes.concat(kemToken, sharedSecret);
    const kemKey = await Hkdf.compute(
        keySizeInBytes, hkdfHash, hkdfIkm, hkdfInfo, opt_hkdfSalt);
    return {'key': kemKey, 'token': kemToken};
  }
}

exports = EciesHkdfKemSender;
