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

goog.module('tink.subtle.EcdsaVerify');

const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const PublicKeyVerify = goog.require('tink.PublicKeyVerify');
const SecurityException = goog.require('tink.exception.SecurityException');
const Validators = goog.require('tink.subtle.Validators');

/**
 * Implementation of ECDSA verifying.
 *
 * @implements {PublicKeyVerify}
 * @public
 * @final
 */
class EcdsaVerify {
  /**
   * @param {!webCrypto.CryptoKey} key
   * @param {string} hash
   * @param {!EllipticCurves.EcdsaSignatureEncodingType} encoding The
   *     encoding of the signature.
   */
  constructor(key, hash, encoding) {
    /** @const @private {!webCrypto.CryptoKey} */
    this.key_ = key;

    /** @const @private {string} */
    this.hash_ = hash;

    /** @const @private {!EllipticCurves.EcdsaSignatureEncodingType} */
    this.encoding_ = encoding;

    /** @const @private {number} */
    this.ieeeSignatureLength_ = 2 *
        EllipticCurves.fieldSizeInBytes(
            EllipticCurves.curveFromString(key.algorithm['namedCurve']));
  }

  /**
   * @param {!webCrypto.JsonWebKey} jwk
   * @param {string} hash
   * @param {?EllipticCurves.EcdsaSignatureEncodingType=} opt_encoding The
   *     optional encoding of the signature. If absent, default is IEEE P1363.
   *
   * @return {!Promise<!PublicKeyVerify>}
   * @static
   */
  static async newInstance(jwk, hash, opt_encoding) {
    if (!jwk) {
      throw new SecurityException('public key has to be non-null');
    }
    Validators.validateEcdsaParams(jwk.crv, hash);
    const cryptoKey = await EllipticCurves.importPublicKey('ECDSA', jwk);
    if (!opt_encoding) {
      opt_encoding = EllipticCurves.EcdsaSignatureEncodingType.IEEE_P1363;
    }
    return new EcdsaVerify(cryptoKey, hash, opt_encoding);
  }

  /**
   * @override
   */
  async verify(signature, data) {
    Validators.requireUint8Array(signature);
    Validators.requireUint8Array(data);
    if (this.encoding_ == EllipticCurves.EcdsaSignatureEncodingType.DER) {
      signature =
          EllipticCurves.ecdsaDer2Ieee(signature, this.ieeeSignatureLength_);
    }
    return await window.crypto.subtle.verify(
        {
          name: 'ECDSA',
          hash: {
            name: this.hash_,
          },
        },
        this.key_, signature, data);
  }
}

exports = EcdsaVerify;
