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
const {InvalidArgumentsException} = goog.require('google3.third_party.tink.javascript.exception.invalid_arguments_exception');

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
 * Supported ECDSA signature encoding.
 * @enum {number}
 */
const EcdsaSignatureEncodingType = {
  // The DER signature is encoded using ASN.1
  // (https://tools.ietf.org/html/rfc5480#appendix-A):
  // ECDSA-Sig-Value :: = SEQUENCE { r INTEGER, s INTEGER }. In particular, the
  // encoding is:
  // 0x30 || totalLength || 0x02 || r's length || r || 0x02 || s's length || s.
  DER: 1,
  // The IEEE_P1363 signature's format is r || s, where r and s are zero-padded
  // and have the same size in bytes as the order of the curve. For example, for
  // NIST P-256 curve, r and s are zero-padded to 32 bytes.
  IEEE_P1363: 2,
};

/**
 * Transform an ECDSA signature in DER encoding to IEEE P1363 encoding.
 *
 * @param {!Uint8Array} der the ECDSA signature in DER encoding
 * @param {number} ieeeLength the length of the ECDSA signature in IEEE
 *     encoding. This is usually 2 * size of the elliptic curve field.
 * @return {!Uint8Array} ECDSA signature in IEEE encoding
 */
const ecdsaDer2Ieee = function(der, ieeeLength) {
  if (!isValidDerEcdsaSignature(der)) {
    throw new InvalidArgumentsException('invalid DER signature');
  }
  if (!Number.isInteger(ieeeLength) || ieeeLength < 0) {
    throw new InvalidArgumentsException(
        'ieeeLength must be a nonnegative integer');
  }
  const ieee = new Uint8Array(ieeeLength);
  const length = der[1] & 0xff;
  let offset = 1 /* 0x30 */ + 1 /* totalLength */;
  if (length >= 128) {
    offset++;  // Long form length
  }
  offset++;  // 0x02
  const rLength = der[offset++];
  let extraZero = 0;
  if (der[offset] === 0) {
    extraZero = 1;
  }
  const rOffset = ieeeLength / 2 - rLength + extraZero;
  ieee.set(der.subarray(offset + extraZero, offset + rLength), rOffset);
  offset += rLength /* r byte array */ + 1 /* 0x02 */;
  const sLength = der[offset++];
  extraZero = 0;
  if (der[offset] === 0) {
    extraZero = 1;
  }
  const sOffset = ieeeLength - sLength + extraZero;
  ieee.set(der.subarray(offset + extraZero, offset + sLength), sOffset);
  return ieee;
};

/**
 * Transform an ECDSA signature in IEEE 1363 encoding to DER encoding.
 *
 * @param {!Uint8Array} ieee the ECDSA signature in IEEE encoding
 * @return {!Uint8Array} ECDSA signature in DER encoding
 */
const ecdsaIeee2Der = function(ieee) {
  if (ieee.length % 2 != 0 || ieee.length == 0 || ieee.length > 132) {
    throw new InvalidArgumentsException(
        'Invalid IEEE P1363 signature encoding. Length: ' + ieee.length);
  }
  const r = toUnsignedBigNum(ieee.subarray(0, ieee.length / 2));
  const s = toUnsignedBigNum(ieee.subarray(ieee.length / 2, ieee.length));

  let offset = 0;
  const length = 1 + 1 + r.length + 1 + 1 + s.length;
  let der;
  if (length >= 128) {
    der = new Uint8Array(length + 3);
    der[offset++] = 0x30;
    der[offset++] = 0x80 + 0x01;
    der[offset++] = length;
  } else {
    der = new Uint8Array(length + 2);
    der[offset++] = 0x30;
    der[offset++] = length;
  }
  der[offset++] = 0x02;
  der[offset++] = r.length;
  der.set(r, offset);
  offset += r.length;
  der[offset++] = 0x02;
  der[offset++] = s.length;
  der.set(s, offset);
  return der;
};

/**
 * Validate that the ECDSA signature is in DER encoding, based on
 * https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki.
 *
 * @param {!Uint8Array} sig an ECDSA siganture
 * @return {boolean}
 */
const isValidDerEcdsaSignature = function(sig) {
  // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
  // * total-length: 1-byte or 2-byte length descriptor of everything that
  // follows.
  // * R-length: 1-byte length descriptor of the R value that follows.
  // * R: arbitrary-length big-endian encoded R value. It must use the shortest
  //   possible encoding for a positive integers (which means no null bytes at
  //   the start, except a single one when the next byte has its highest bit
  //   set).
  // * S-length: 1-byte length descriptor of the S value that follows.
  // * S: arbitrary-length big-endian encoded S value. The same rules apply.
  if (sig.length < 1 /* 0x30 */
          + 1        /* total-length */
          + 1        /* 0x02 */
          + 1        /* R-length */
          + 1        /* R */
          + 1        /* 0x02 */
          + 1        /* S-length */
          + 1 /* S */) {
    // Signature is too short.
    return false;
  }

  // Checking bytes from left to right.

  // byte #1: a signature is of type 0x30 (compound).
  if (sig[0] != 0x30) {
    return false;
  }

  // byte #2 and maybe #3: the total length of the signature.
  let totalLen = sig[1] & 0xff;
  let totalLenLen =
      1;  // the length of the total length field, could be 2-byte.
  if (totalLen == 129) {
    // The signature is >= 128 bytes thus total length field is in long-form
    // encoding and occupies 2 bytes.
    totalLenLen = 2;
    // byte #3 is the total length.
    totalLen = sig[2] & 0xff;
    if (totalLen < 128) {
      // Length in long-form encoding must be >= 128.
      return false;
    }
  } else if (totalLen == 128 || totalLen > 129) {
    // Impossible values for the second byte.
    return false;
  }

  // Make sure the length covers the entire sig.
  if (totalLen != sig.length - 1 - totalLenLen) {
    return false;
  }

  // Start checking R.
  // Check whether the R element is an integer.
  if (sig[1 + totalLenLen] != 0x02) {
    return false;
  }
  // Extract the length of the R element.
  const rLen = sig[1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */] & 0xff;
  // Make sure the length of the S element is still inside the signature.
  if (1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */ + 1 /* rLen */ + rLen +
          1 /* 0x02 */
      >= sig.length) {
    return false;
  }
  // Zero-length integers are not allowed for R.
  if (rLen == 0) {
    return false;
  }
  // Negative numbers are not allowed for R.
  if ((sig[3 + totalLenLen] & 0xff) >= 128) {
    return false;
  }
  // Null bytes at the start of R are not allowed, unless R would
  // otherwise be interpreted as a negative number.
  if (rLen > 1 && (sig[3 + totalLenLen] == 0x00) &&
      ((sig[4 + totalLenLen] & 0xff) < 128)) {
    return false;
  }

  // Start checking S.
  // Check whether the S element is an integer.
  if (sig[3 + totalLenLen + rLen] != 0x02) {
    return false;
  }
  // Extract the length of the S element.
  const sLen = sig[1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */ + 1 /* rLen */ +
                   rLen + 1 /* 0x02 */] &
      0xff;
  // Verify that the length of the signature matches the sum of the length of
  // the elements.
  if (1                     /* 0x30 */
          + totalLenLen + 1 /* 0x02 */
          + 1               /* rLen */
          + rLen + 1        /* 0x02 */
          + 1               /* sLen */
          + sLen !=
      sig.length) {
    return false;
  }
  // Zero-length integers are not allowed for S.
  if (sLen == 0) {
    return false;
  }
  // Negative numbers are not allowed for S.
  if ((sig[5 + totalLenLen + rLen] & 0xff) >= 128) {
    return false;
  }
  // Null bytes at the start of S are not allowed, unless S would
  // otherwise be interpreted as a negative number.
  if (sLen > 1 && (sig[5 + totalLenLen + rLen] == 0x00) &&
      ((sig[6 + totalLenLen + rLen] & 0xff) < 128)) {
    return false;
  }

  return true;
};

/**
 * Transform a big integer in big endian to minimal unsigned form which has
 * no extra zero at the beginning except when the highest bit is set.
 *
 * @param {!Uint8Array} bytes
 * @return {!Uint8Array}
 */
const toUnsignedBigNum = function(bytes) {
  // Remove zero prefixes.
  let start = 0;
  while (start < bytes.length && bytes[start] == 0) {
    start++;
  }
  if (start == bytes.length) {
    start = bytes.length - 1;
  }

  let extraZero = 0;
  // If the 1st bit is not zero, add 1 zero byte.
  if ((bytes[start] & 0x80) == 0x80) {
    // Add extra zero.
    extraZero = 1;
  }
  const res = new Uint8Array(bytes.length - start + extraZero);
  res.set(bytes.subarray(start), extraZero);
  return res;
};

/**
 * @param {!CurveType} curve
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
 * @return {!CurveType}
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
 * @param {!PointFormatType} format
 * @param {!webCrypto.JsonWebKey} point
 * @return {!Uint8Array}
 */
const pointEncode = function(curve, format, point) {
  const fieldSize = fieldSizeInBytes(curveFromString(curve));
  switch (format) {
    case PointFormatType.UNCOMPRESSED:
      let result = new Uint8Array(1 + 2 * fieldSize);
      result[0] = 0x04;
      result.set(Bytes.fromBase64(point.x, /* opt_webSafe = */ true), 1);
      result.set(
          Bytes.fromBase64(point.y, /* opt_webSafe = */ true), 1 + fieldSize);
      return result;
  }
  throw new InvalidArgumentsException('invalid format');
};

/**
 * @param {string} curve
 * @param {!PointFormatType} format
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
            new Uint8Array(point.subarray(1, 1 + fieldSize)),
            true /* websafe */),
        'y': Bytes.toBase64(
            new Uint8Array(point.subarray(1 + fieldSize, point.length)),
            true /* websafe */),
        'ext': true,
      });
      return result;
  }
  throw new InvalidArgumentsException('invalid format');
};

/**
 * @param {!CurveType} curve
 * @param {!Uint8Array} x
 * @param {!Uint8Array} y
 * @param {?Uint8Array=} d
 *
 * @return {!webCrypto.JsonWebKey}
 */
const getJsonWebKey = function(curve, x, y, d) {
  const key = /** @type {!webCrypto.JsonWebKey} */ ({
    'kty': 'EC',
    'crv': curveToString(curve),
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

/**
 * @param {!CurveType} curve
 * @param {!PointFormatType} pointFormat
 *
 * @return {number}
 */
const encodingSizeInBytes = function(curve, pointFormat) {
  switch (pointFormat) {
    case PointFormatType.UNCOMPRESSED:
      return 2 * fieldSizeInBytes(curve) + 1;
    case PointFormatType.COMPRESSED:
      return fieldSizeInBytes(curve) + 1;
    case PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
      return 2 * fieldSizeInBytes(curve);
  }
  throw new InvalidArgumentsException('invalid format');
};

/**
 * @param {!webCrypto.CryptoKey} privateKey
 * @param {!webCrypto.CryptoKey} publicKey
 * @return {!Promise<!Uint8Array>}
 */
const computeEcdhSharedSecret = async function(privateKey, publicKey) {
  const ecdhParams =
      /** @type {!webCrypto.AlgorithmIdentifier} */ (privateKey.algorithm);
  ecdhParams['public'] = publicKey;
  const fieldSizeInBits =
      8 * fieldSizeInBytes(curveFromString(ecdhParams['namedCurve']));
  const sharedSecret = await window.crypto.subtle.deriveBits(
      ecdhParams, privateKey, fieldSizeInBits);
  return new Uint8Array(sharedSecret);
};

/**
 * @param {string} algorithm
 * @param {string} curve
 * @return {!Promise<!webCrypto.CryptoKeyPair>}
 */
const generateKeyPair = async function(algorithm, curve) {
  if (algorithm != 'ECDH' && algorithm != 'ECDSA') {
    throw new InvalidArgumentsException(
        'algorithm must be either ECDH or ECDSA');
  }
  const params = /** @type {!webCrypto.AlgorithmIdentifier} */ (
      {'name': algorithm, 'namedCurve': curve});
  const ephemeralKeyPair = await window.crypto.subtle.generateKey(
      params, true /* extractable */,
      algorithm == 'ECDH' ? ['deriveKey', 'deriveBits'] :
                            ['sign', 'verify'] /* usage */);
  return /** @type {!webCrypto.CryptoKeyPair} */ (ephemeralKeyPair);
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
 * @param {string} algorithm
 * @param {!webCrypto.JsonWebKey} jwk
 * @return {!Promise<!webCrypto.CryptoKey>}
 */
const importPublicKey = async function(algorithm, jwk) {
  if (algorithm != 'ECDH' && algorithm != 'ECDSA') {
    throw new InvalidArgumentsException(
        'algorithm must be either ECDH or ECDSA');
  }
  const publicKey = await window.crypto.subtle.importKey(
      'jwk' /* format */, jwk,
      {'name': algorithm, 'namedCurve': jwk.crv} /* algorithm */,
      true /* extractable */,
      algorithm == 'ECDH' ? [] : ['verify'] /* usage */);
  return publicKey;
};

/**
 * @param {string} algorithm
 * @param {!webCrypto.JsonWebKey} jwk
 * @return {!Promise<!webCrypto.CryptoKey>}
 */
const importPrivateKey = async function(algorithm, jwk) {
  if (algorithm != 'ECDH' && algorithm != 'ECDSA') {
    throw new InvalidArgumentsException(
        'algorithm must be either ECDH or ECDSA');
  }
  const privateKey = await window.crypto.subtle.importKey(
      'jwk' /* format */, jwk /* key material */,
      {'name': algorithm, 'namedCurve': jwk.crv} /* algorithm */,
      true /* extractable */,
      algorithm == 'ECDH' ? ['deriveKey', 'deriveBits'] : ['sign'] /* usage */);
  return privateKey;
};

exports = {
  CurveType,
  EcdsaSignatureEncodingType,
  PointFormatType,
  computeEcdhSharedSecret,
  curveToString,
  curveFromString,
  ecdsaDer2Ieee,
  ecdsaIeee2Der,
  getJsonWebKey,
  isValidDerEcdsaSignature,
  encodingSizeInBytes,
  exportCryptoKey,
  fieldSizeInBytes,
  generateKeyPair,
  importPrivateKey,
  importPublicKey,
  pointDecode,
  pointEncode,
};
