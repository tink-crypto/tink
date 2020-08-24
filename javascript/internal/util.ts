/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as Bytes from '../subtle/bytes';
import * as EllipticCurves from '../subtle/elliptic_curves';

import {PbEllipticCurveType, PbHashType, PbKeyset, PbKeysetKey, PbKeyStatusType, PbOutputPrefixType, PbPointFormat} from './proto';

/**
 * A type representing the constructor function for a given class. Unlike
 * TypeScript's built-in `new` types, this works with abstract classes. It is
 * used to describe the relationship between a primitive type object and its
 * instances.
 */
export type Constructor<T> = Function&{prototype: T};

/** Like the `instanceof` operator, but works with `Constructor`. */
export function isInstanceOf<T>(
    value: unknown, ctor: Constructor<T>): value is T {
  return value instanceof ctor;
}

/**
 * Validates the given key and throws SecurityException if it is invalid.
 *
 */
export function validateKey(key: PbKeysetKey) {
  if (!key) {
    throw new SecurityException('Key should be non null.');
  }
  if (!key.getKeyData()) {
    throw new SecurityException(
        'Key data are missing for key ' + key.getKeyId() + '.');
  }
  if (key.getOutputPrefixType() === PbOutputPrefixType.UNKNOWN_PREFIX) {
    throw new SecurityException(
        'Key ' + key.getKeyId() + ' has unknown output prefix type.');
  }
  if (key.getStatus() === PbKeyStatusType.UNKNOWN_STATUS) {
    throw new SecurityException(
        'Key ' + key.getKeyId() + ' has unknown status.');
  }
}

/**
 * Validates the given keyset and throws SecurityException if it is invalid.
 *
 */
export function validateKeyset(keyset: PbKeyset) {
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
    throw new SecurityException(
        'Primary key has to be in the keyset and ' +
        'has to be enabled.');
  }
}

// Functions which are useful for implementation of
// private and public EC keys.

/**
 * Either prolong or shrinks the array representing number in BigEndian encoding
 * to have the specified size. As webcrypto API assumes that x, y and d values
 * has exactly the supposed number of bytes, whereas corresponding x, y and
 * keyValue values in proto might either have some leading zeros or the leading
 * zeros might be missing.
 *
 */
export function bigEndianNumberToCorrectLength(
    bigEndianNumber: Uint8Array, sizeInBytes: number): Uint8Array {
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
}

export function curveTypeProtoToSubtle(curveTypeProto: PbEllipticCurveType):
    EllipticCurves.CurveType {
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
}

export function hashTypeProtoToString(hashTypeProto: PbHashType): string {
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
}

export function pointFormatProtoToSubtle(pointFormatProto: PbPointFormat):
    EllipticCurves.PointFormatType {
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
}
