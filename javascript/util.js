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

goog.module('tink.Util');

const Bytes = goog.require('tink.subtle.Bytes');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const PbPointFormat = goog.require('proto.google.crypto.tink.EcPointFormat');
const SecurityException = goog.require('tink.exception.SecurityException');

/**
 * Validates the given key and throws SecurityException if it is invalid.
 *
 * @param {!PbKeyset.Key} key
 */
const validateKey = function(key) {
  if (!key) {
    throw new SecurityException('Key should be non null.');
  }
  if (!key.getKeyData()) {
    throw new SecurityException('Key data are missing for key '
        + key.getKeyId() + '.');
  }
  if (key.getOutputPrefixType() === PbOutputPrefixType.UNKNOWN_PREFIX) {
    throw new SecurityException('Key ' + key.getKeyId() +
        ' has unknown output prefix type.');
  }
  if (key.getStatus() === PbKeyStatusType.UNKNOWN_STATUS) {
    throw new SecurityException('Key ' + key.getKeyId() +
        ' has unknown status.');
  }
};

/**
 * Validates the given keyset and throws SecurityException if it is invalid.
 *
 * @param {!PbKeyset} keyset
 */
const validateKeyset = function(keyset) {
  if (!keyset || !keyset.getKeyList() || keyset.getKeyList().length < 1) {
    throw new SecurityException(
        'Keyset should be non null and must contain at least one key.');
  }

  let hasPrimary = false;
  const numberOfKeys = keyset.getKeyList().length;
  for (let i = 0; i < numberOfKeys; i++) {
    const key = keyset.getKeyList()[i];
    validateKey(key);
    if (keyset.getPrimaryKeyId() === key.getKeyId() &&
        key.getStatus() === PbKeyStatusType.ENABLED) {
      if (hasPrimary) {
        throw new SecurityException('Primary key has to be unique.');
      }
      hasPrimary = true;
    }
  }

  if (!hasPrimary) {
    throw new SecurityException('Primary key has to be in the keyset and ' +
        'has to be enabled.');
  }
};

// Functions which are useful for implementation of
// private and public EC keys.

/**
 * Either prolong or shrinks the array representing number in BigEndian encoding
 * to have the specified size. As webcrypto API assumes that x, y and d values
 * has exactly the supposed number of bytes, whereas corresponding x, y and
 * keyValue values in proto might either have some leading zeros or the leading
 * zeros might be missing.
 *
 * @param {!Uint8Array} bigEndianNumber
 * @param {number} sizeInBytes
 * @return {!Uint8Array}
 */
const bigEndianNumberToCorrectLength = function(bigEndianNumber, sizeInBytes) {
  const numberLen = bigEndianNumber.length;
  if (numberLen < sizeInBytes) {
    const zeros = new Uint8Array(sizeInBytes - numberLen);
    return Bytes.concat(zeros, bigEndianNumber);
  }
  if (numberLen > sizeInBytes) {
    for (let i = 0; i < numberLen - sizeInBytes; i++) {
      if (bigEndianNumber[i] != 0) {
        throw new SecurityException(
            'Number needs more bytes to be represented.');
      }
    }
    return bigEndianNumber.slice(numberLen - sizeInBytes, numberLen);
  }
  return bigEndianNumber;
};

/**
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
  bigEndianNumberToCorrectLength,
  curveTypeProtoToSubtle,
  hashTypeProtoToString,
  pointFormatProtoToSubtle,
  validateKey,
  validateKeyset,
};
