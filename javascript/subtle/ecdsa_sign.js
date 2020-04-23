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

goog.module('tink.subtle.EcdsaSign');

const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const {PublicKeySign} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_sign');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const Validators = goog.require('tink.subtle.Validators');

/**
 * Implementation of ECDSA signing.
 *
 * @public
 * @final
 */
class EcdsaSign extends PublicKeySign {
  /**
   * @param {!webCrypto.CryptoKey} key
   * @param {string} hash
   * @param {?EllipticCurves.EcdsaSignatureEncodingType=} opt_encoding The
   *     optional encoding of the signature. If absent, default is IEEE P1363.
   */
  constructor(key, hash, opt_encoding) {
    super();

    /** @const @private {!webCrypto.CryptoKey} */
    this.key_ = key;

    /** @const @private {string} */
    this.hash_ = hash;

    if (!opt_encoding) {
      opt_encoding = EllipticCurves.EcdsaSignatureEncodingType.IEEE_P1363;
    }

    /** @const @private {!EllipticCurves.EcdsaSignatureEncodingType} */
    this.encoding_ = opt_encoding;
  }

  /**
   * @param {!webCrypto.JsonWebKey} jwk
   * @param {string} hash
   * @param {?EllipticCurves.EcdsaSignatureEncodingType=} opt_encoding The
   *     optional encoding of the signature. If absent, default is IEEE P1363.
   *
   * @return {!Promise<!PublicKeySign>}
   * @static
   */
  static async newInstance(jwk, hash, opt_encoding) {
    if (!jwk) {
      throw new SecurityException('private key has to be non-null');
    }
    Validators.validateEcdsaParams(jwk.crv, hash);
    const cryptoKey = await EllipticCurves.importPrivateKey('ECDSA', jwk);
    return new EcdsaSign(cryptoKey, hash, opt_encoding);
  }

  /**
   * @override
   */
  async sign(data) {
    Validators.requireUint8Array(data);
    const signature = await window.crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: {
            name: this.hash_,
          },
        },
        this.key_, data);

    if (this.encoding_ == EllipticCurves.EcdsaSignatureEncodingType.DER) {
      return EllipticCurves.ecdsaIeee2Der(new Uint8Array(signature));
    }
    return new Uint8Array(signature);
  }
}

exports = EcdsaSign;
