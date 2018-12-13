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

goog.module('tink.hybrid.EciesAeadHkdfUtil');

const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const PbEciesAeadHkdfPrivateKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPrivateKey');
const PbEciesAeadHkdfPublicKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPublicKey');
const Util = goog.require('tink.Util');

// This file contains only functions which are useful for implementation of
// private and public ECIES AEAD HKDF key manager.

/**
 * WARNING: This method assumes that the given key proto is valid.
 *
 * @package
 * @param {!PbEciesAeadHkdfPrivateKey|!PbEciesAeadHkdfPublicKey} key
 * @return {!webCrypto.JsonWebKey}
 */
const getJsonWebKeyFromProto = function(key) {
  let /** @type {!PbEciesAeadHkdfPublicKey} */ publicKey;
  let /** @type {!Uint8Array} */ d;
  if (key instanceof PbEciesAeadHkdfPrivateKey) {
    publicKey = /** @type{!PbEciesAeadHkdfPublicKey} */ (key.getPublicKey());
  } else {
    publicKey = key;
  }

  const curveType = Util.curveTypeProtoToSubtle(
      publicKey.getParams().getKemParams().getCurveType());
  const expectedLength = EllipticCurves.fieldSizeInBytes(curveType);
  let x = Util.bigEndianNumberToCorrectLength(
      publicKey.getX_asU8(), expectedLength);
  let y = Util.bigEndianNumberToCorrectLength(
      publicKey.getY_asU8(), expectedLength);
  if (key instanceof PbEciesAeadHkdfPrivateKey) {
    d = Util.bigEndianNumberToCorrectLength(
        key.getKeyValue_asU8(), expectedLength);
  }
  return EllipticCurves.getJsonWebKey(curveType, x, y, d);
};

exports = {
  getJsonWebKeyFromProto,
};
