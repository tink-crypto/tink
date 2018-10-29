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

goog.module('tink.subtle.webcrypto.Ecdh');

const EllipticCurves = goog.require('tink.subtle.EllipticCurves');

/**
 * @param {!webCrypto.CryptoKey} privateKey
 * @param {!webCrypto.CryptoKey} publicKey
 * @return {!Promise<!Uint8Array>}
 */
const computeSharedSecret = async function(privateKey, publicKey) {
  const ecdhParams =
      /** @type {!webCrypto.AlgorithmIdentifier} */ (privateKey.algorithm);
  ecdhParams['public'] = publicKey;
  const fieldSizeInBits = 8 *
      EllipticCurves.fieldSizeInBytes(
          EllipticCurves.curveFromString(ecdhParams['namedCurve']));
  const sharedSecret = await window.crypto.subtle.deriveBits(
      ecdhParams, privateKey, fieldSizeInBits);
  return new Uint8Array(sharedSecret);
};

/**
 * @param {string} curve
 * @return {!Promise<!webCrypto.CryptoKey>}
 */
const generateKeyPair = async function(curve) {
  const ecdhParams = /** @type {!webCrypto.AlgorithmIdentifier} */ (
      {'name': 'ECDH', 'namedCurve': curve});
  const ephemeralKeyPair = await window.crypto.subtle.generateKey(
      ecdhParams, true /* extractable */,
      ['deriveKey', 'deriveBits'] /* usage */);
  return /** @type {!webCrypto.CryptoKey} */ (ephemeralKeyPair);
};

/**
 * @param {!webCrypto.CryptoKey} cryptoKey
 * @return {!Promise<!webCrypto.JsonWebKey>}
 */
const exportCryptoKey = async function(cryptoKey) {
  const jwk = await window.crypto.subtle.exportKey('jwk', cryptoKey);
  return /** @type {!webCrypto.JsonWebKey} */ (jwk);
};

/**
 * @param {!webCrypto.JsonWebKey} jwk
 * @return {!Promise<!webCrypto.CryptoKey>}
 */
const importPublicKey = async function(jwk) {
  const publicKey = await window.crypto.subtle.importKey(
      'jwk' /* format */, jwk,
      {'name': 'ECDH', 'namedCurve': jwk.crv} /* algorithm */,
      true /* extractable */, [] /* usage, empty for public key */);
  return publicKey;
};

/**
 * @param {!webCrypto.JsonWebKey} jwk
 * @return {!Promise<!webCrypto.CryptoKey>}
 */
const importPrivateKey = async function(jwk) {
  const privateKey = await window.crypto.subtle.importKey(
      'jwk' /* format */, jwk /* key material */,
      {'name': 'ECDH', 'namedCurve': jwk.crv} /* algorithm */,
      true /* extractable */, ['deriveKey', 'deriveBits'] /* usage */);
  return privateKey;
};

exports = {
  computeSharedSecret,
  generateKeyPair,
  exportCryptoKey,
  importPublicKey,
  importPrivateKey,
};
