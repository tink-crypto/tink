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

const Bytes = goog.require('tink.subtle.Bytes');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const PbEciesAeadHkdfPrivateKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPrivateKey');
const PbEciesAeadHkdfPublicKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPublicKey');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbPointFormat = goog.require('proto.google.crypto.tink.EcPointFormat');
const SecurityException = goog.require('tink.exception.SecurityException');

// This file contains only functions which are useful for implementation of
// private and public ECIES AEAD HKDF key manager.


/**
 * @package
 * @param {!PbEllipticCurveType} curveTypeProto
 * @return {!EllipticCurves.CurveType}
 */
const curveTypeProtoToSubtle = function(curveTypeProto) {
  switch (curveTypeProto) {
    case PbEllipticCurveType.NIST_P256:
      return EllipticCurves.CurveType.P256;
    case PbEllipticCurveType.NIST_P384:
      return EllipticCurves.CurveType.P384;
    case PbEllipticCurveType.NIST_P521:
      return EllipticCurves.CurveType.P521;
    default:
      throw new SecurityException('Unknown curve type.');
  }
};

/**
 * @private
 * @param {EllipticCurves.CurveType} curve
 * @param {!Uint8Array} x
 * @param {!Uint8Array} y
 * @param {?Uint8Array=} d
 *
 * @return {!webCrypto.JsonWebKey}
 */
const getJsonKey = function(curve, x, y, d) {
  const key = /** @type {!webCrypto.JsonWebKey} */ ({
    'kty': 'EC',
    'crv': EllipticCurves.curveToString(curve),
    'x': Bytes.toBase64(x, true /* websafe */),
    'y': Bytes.toBase64(y, true /* websafe */),
    'ext': true,
  });
  if (d) {
    key['d'] = Bytes.toBase64(d, true /* websafe */);
  }
  return key;
};

/**
 * Either prolong or shrinks the array representing x or y coordinate to have
 * the specified size. As webcrypto API assumes that x and y coordinates has
 * exactly the supposed number of bytes, whereas x and y in proto might either
 * have some leading zeros or the leading zeros might be missing.
 *
 * @private
 * @param {!Uint8Array} coordinate represented in BigEndian
 * @param {number} sizeInBytes
 * @return {!Uint8Array}
 */
const coordinateToCorrectLength = function(coordinate, sizeInBytes) {
  const coordLen = coordinate.length;
  if (coordLen < sizeInBytes) {
    const zeros = new Uint8Array(sizeInBytes - coordLen);
    return Bytes.concat(zeros, coordinate);
  }
  if (coordLen > sizeInBytes) {
    for (let i = 0; i < coordLen - sizeInBytes; i++) {
      if (coordinate[i] != 0) {
        throw new SecurityException(
            'Number needs more bytes to be represented.');
      }
    }
    return coordinate.slice(coordLen - sizeInBytes, coordLen);
  }
  return coordinate;
};

/**
 * WARNING: This method assumes that the given key proto is valid.
 *
 * @package
 * @param {!PbEciesAeadHkdfPrivateKey|!PbEciesAeadHkdfPublicKey} key
 * @return {!webCrypto.JsonWebKey}
 */
const getJsonKeyFromProto = function(key) {
  let /** @type {!PbEciesAeadHkdfPublicKey} */ publicKey;
  let /** @type {!Uint8Array} */ d;
  if (key instanceof PbEciesAeadHkdfPrivateKey) {
    publicKey = /** @type{!PbEciesAeadHkdfPublicKey} */ (key.getPublicKey());
    d = /** @type{!Uint8Array} */ (key.getKeyValue_asU8());
  } else {
    publicKey = key;
  }

  const curveType = curveTypeProtoToSubtle(
      publicKey.getParams().getKemParams().getCurveType());
  const coordinateLength = EllipticCurves.fieldSizeInBytes(curveType);
  let x = coordinateToCorrectLength(publicKey.getX_asU8(), coordinateLength);
  let y = coordinateToCorrectLength(publicKey.getY_asU8(), coordinateLength);
  return getJsonKey(curveType, x, y, d);
};

/**
 * @package
 * @param {!PbHashType} hashTypeProto
 * @return {string}
 */
const hashTypeProtoToString = function(hashTypeProto) {
  switch (hashTypeProto) {
    case PbHashType.SHA1:
      return 'SHA-1';
    case PbHashType.SHA256:
      return 'SHA-256';
    case PbHashType.SHA512:
      return 'SHA-512';
    default:
      throw new SecurityException('Unknown hash type.');
  }
};

/**
 * @package
 * @param {!PbPointFormat} pointFormatProto
 * @return {!EllipticCurves.PointFormatType}
 */
const pointFormatProtoToSubtle = function(pointFormatProto) {
  switch (pointFormatProto) {
    case PbPointFormat.UNCOMPRESSED:
      return EllipticCurves.PointFormatType.UNCOMPRESSED;
    case PbPointFormat.COMPRESSED:
      return EllipticCurves.PointFormatType.COMPRESSED;
    case PbPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
      return EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED;
    default:
      throw new SecurityException('Unknown point format.');
  }
};

exports = {
  curveTypeProtoToSubtle,
  getJsonKeyFromProto,
  hashTypeProtoToString,
  pointFormatProtoToSubtle,
};
