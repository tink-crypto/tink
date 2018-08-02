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

/**
 * @fileoverview Common enums.
 */

goog.module('tink.subtle.EllipticCurves');

const Bytes = goog.require('tink.subtle.Bytes');
const InvalidArgumentsException = goog.require('tink.exception.InvalidArgumentsException');
const array = goog.require('goog.array');

/**
 * Supported elliptic curves.
 * @enum {number}
 */
const CurveType = {
  P256: 1,
  P384: 2,
  P521: 3,
};

/**
 * Supported point format.
 * @enum {number}
 */
const PointFormatType = {
  UNCOMPRESSED: 1,
  COMPRESSED: 2,
  // Like UNCOMPRESSED but without the \x04 prefix. Crunchy uses this format.
  // DO NOT USE unless you are a Crunchy user moving to Tink.
  DO_NOT_USE_CRUNCHY_UNCOMPRESSED: 3,
};

/**
 * @param {CurveType} curve
 * @return {string}
 */
const curveToString = function(curve) {
  switch (curve) {
    case CurveType.P256:
      return 'P-256';
    case CurveType.P384:
      return 'P-384';
    case CurveType.P521:
      return 'P-521';
  }
  throw new InvalidArgumentsException('unknown curve: ' + curve);
};

/**
 * @param {string} curve
 * @return {CurveType}
 */
const curveFromString = function(curve) {
  switch (curve) {
    case 'P-256':
      return CurveType.P256;
    case 'P-384':
      return CurveType.P384;
    case 'P-521':
      return CurveType.P521;
  }
  throw new InvalidArgumentsException('unknown curve: ' + curve);
};

/**
 * @param {string} curve
 * @param {PointFormatType} format
 * @param {!webCrypto.JsonWebKey} point
 * @return {!Uint8Array}
 */
const pointEncode = function(curve, format, point) {
  const fieldSize = fieldSizeInBytes(curveFromString(curve));
  switch (format) {
    case PointFormatType.UNCOMPRESSED:
      let result = new Uint8Array(1 + 2 * fieldSize);
      result[0] = 0x04;
      result.set(Bytes.fromBase64(point.x), 1);
      result.set(Bytes.fromBase64(point.y), 1 + fieldSize);
      return result;
  }
  throw new InvalidArgumentsException('invalid format');
};

/**
 * @param {string} curve
 * @param {PointFormatType} format
 * @param {!Uint8Array} point
 * @return {!webCrypto.JsonWebKey}
 */
const pointDecode = function(curve, format, point) {
  const fieldSize = fieldSizeInBytes(curveFromString(curve));
  switch (format) {
    case PointFormatType.UNCOMPRESSED:
      if (point.length != 1 + 2 * fieldSize || point[0] != 0x04) {
        throw new InvalidArgumentsException('invalid point');
      }
      let result = /** @type {!webCrypto.JsonWebKey} */ ({
        'kty': 'EC',
        'crv': curve,
        'x': Bytes.toBase64(
            new Uint8Array(array.slice(point, 1, 1 + fieldSize)),
            true /* websafe */),
        'y': Bytes.toBase64(
            new Uint8Array(array.slice(point, 1 + fieldSize, point.length)),
            true /* websafe */),
        'ext': true,
      });
      return result;
  }
  throw new InvalidArgumentsException('invalid format');
};

/**
 * @param {!CurveType} curve
 * @return {number}
 */
const fieldSizeInBytes = function(curve) {
  switch (curve) {
    case CurveType.P256:
      return 32;
    case CurveType.P384:
      return 48;
    case CurveType.P521:
      return 66;
  }
  throw new InvalidArgumentsException('unknown curve: ' + curve);
};

exports = {
  CurveType,
  PointFormatType,
  curveToString,
  curveFromString,
  pointDecode,
  pointEncode,
  fieldSizeInBytes,
};
