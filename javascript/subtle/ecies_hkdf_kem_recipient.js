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

goog.module('tink.subtle.EciesHkdfKemRecipient');

const Bytes = goog.require('tink.subtle.Bytes');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Hkdf = goog.require('tink.subtle.Hkdf');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * HKDF-based ECIES-KEM (key encapsulation mechanism) for ECIES recipient.
 */
class EciesHkdfKemRecipient {
  /**
   * @param {!webCrypto.CryptoKey} privateKey
   */
  constructor(privateKey) {
    if (!privateKey) {
      throw new SecurityException('Private key has to be non-null.');
    }
    // CryptoKey should have the properties type and algorithm.
    if (privateKey.type !== 'private' || !privateKey.algorithm) {
      throw new SecurityException('Expected crypto key of type: private.');
    }
    /** @const @private {!webCrypto.CryptoKey} */
    this.privateKey_ = privateKey;
  }

  /**
   * @param {!webCrypto.JsonWebKey} jwk
   * @return {!Promise.<!EciesHkdfKemRecipient>}
   * @static
   */
  static async newInstance(jwk) {
    const privateKey = await EllipticCurves.importPrivateKey('ECDH', jwk);
    return new EciesHkdfKemRecipient(privateKey);
  }

  /**
   * @param {!Uint8Array} kemToken the public ephemeral point.
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
   * @return {!Promise.<!Uint8Array>} The KEM key and token.
   */
  async decapsulate(
      kemToken, keySizeInBytes, pointFormat, hkdfHash, hkdfInfo, opt_hkdfSalt) {
    const jwk = EllipticCurves.pointDecode(
        this.privateKey_.algorithm['namedCurve'], pointFormat, kemToken);
    const publicKey = await EllipticCurves.importPublicKey('ECDH', jwk);
    const sharedSecret = await EllipticCurves.computeEcdhSharedSecret(
        this.privateKey_, publicKey);
    const hkdfIkm = Bytes.concat(kemToken, sharedSecret);
    const kemKey = await Hkdf.compute(
        keySizeInBytes, hkdfHash, hkdfIkm, hkdfInfo, opt_hkdfSalt);
    return kemKey;
  }
}

exports = EciesHkdfKemRecipient;
