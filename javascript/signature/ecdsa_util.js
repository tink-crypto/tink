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

goog.module('tink.signature.EcdsaUtil');

const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const PbEcdsaKeyFormat = goog.require('proto.google.crypto.tink.EcdsaKeyFormat');
const PbEcdsaParams = goog.require('proto.google.crypto.tink.EcdsaParams');
const PbEcdsaPrivateKey = goog.require('proto.google.crypto.tink.EcdsaPrivateKey');
const PbEcdsaPublicKey = goog.require('proto.google.crypto.tink.EcdsaPublicKey');
const PbEcdsaSignatureEncodingType = goog.require('proto.google.crypto.tink.EcdsaSignatureEncoding');
const SecurityException = goog.require('tink.exception.SecurityException');
const Util = goog.require('tink.Util');
const Validators = goog.require('tink.subtle.Validators');

/**
 * @package
 * @param {!PbEcdsaKeyFormat} keyFormat
 */
const validateKeyFormat = function(keyFormat) {
  const params = keyFormat.getParams();
  if (!params) {
    throw new SecurityException('Invalid key format - missing params.');
  }
  validateParams(params);
};

/**
 * @package
 * @param {!PbEcdsaPrivateKey} key
 * @param {number} privateKeyManagerVersion
 * @param {number} publicKeyManagerVersion
 */
const validatePrivateKey = function(
    key, privateKeyManagerVersion, publicKeyManagerVersion) {
  Validators.validateVersion(key.getVersion(), privateKeyManagerVersion);

  if (!key.getKeyValue()) {
    throw new SecurityException(
        'Invalid private key - missing private key value.');
  }

  const publicKey = key.getPublicKey();
  if (!publicKey) {
    throw new SecurityException(
        'Invalid private key - missing public key information.');
  }
  validatePublicKey(publicKey, publicKeyManagerVersion);
};

/**
 * @package
 * @param {!PbEcdsaPublicKey} key
 * @param {number} publicKeyManagerVersion
 */
const validatePublicKey = function(key, publicKeyManagerVersion) {
  Validators.validateVersion(key.getVersion(), publicKeyManagerVersion);

  const params = key.getParams();
  if (!params) {
    throw new SecurityException('Invalid public key - missing params.');
  }
  validateParams(params);

  if (!key.getX() || !key.getY()) {
    throw new SecurityException(
        'Invalid public key - missing value of X or Y.');
  }
};

/**
 * @package
 * @param {!PbEcdsaParams} params
 */
const validateParams = function(params) {
  if (params.getEncoding() === PbEcdsaSignatureEncodingType.UNKNOWN_ENCODING) {
    throw new SecurityException(
        'Invalid public key - missing signature encoding.');
  }

  const hash = Util.hashTypeProtoToString(params.getHashType());
  const curve = EllipticCurves.curveToString(
      Util.curveTypeProtoToSubtle(params.getCurve()));
  Validators.validateEcdsaParams(curve, hash);
};

/**
 * @param {!PbEcdsaSignatureEncodingType} encodingTypeProto
 * @return {!EllipticCurves.EcdsaSignatureEncodingType}
 */
const encodingTypeProtoToEnum = function(encodingTypeProto) {
  switch (encodingTypeProto) {
    case PbEcdsaSignatureEncodingType.DER:
      return EllipticCurves.EcdsaSignatureEncodingType.DER;
    case PbEcdsaSignatureEncodingType.IEEE_P1363:
      return EllipticCurves.EcdsaSignatureEncodingType.IEEE_P1363;
    default:
      throw new SecurityException('Unknown ECDSA signature encoding type.');
  }
};

/**
 * WARNING: This method assumes that the given key proto is valid.
 *
 * @package
 * @param {!PbEcdsaPrivateKey|!PbEcdsaPublicKey} key
 * @return {!webCrypto.JsonWebKey}
 */
const getJsonWebKeyFromProto = function(key) {
  let /** @type {!PbEcdsaPublicKey} */ publicKey;
  let /** @type {!Uint8Array} */ d;
  if (key instanceof PbEcdsaPrivateKey) {
    publicKey = /** @type{!PbEcdsaPublicKey} */ (key.getPublicKey());
  } else {
    publicKey = key;
  }

  const curveType =
      Util.curveTypeProtoToSubtle(publicKey.getParams().getCurve());
  const expectedLength = EllipticCurves.fieldSizeInBytes(curveType);
  let x = Util.bigEndianNumberToCorrectLength(
      publicKey.getX_asU8(), expectedLength);
  let y = Util.bigEndianNumberToCorrectLength(
      publicKey.getY_asU8(), expectedLength);
  if (key instanceof PbEcdsaPrivateKey) {
    d = Util.bigEndianNumberToCorrectLength(
        key.getKeyValue_asU8(), expectedLength);
  }
  return EllipticCurves.getJsonWebKey(curveType, x, y, d);
};

exports = {
  encodingTypeProtoToEnum,
  validateKeyFormat,
  validateParams,
  validatePublicKey,
  validatePrivateKey,
  getJsonWebKeyFromProto,
};
