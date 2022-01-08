/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */


/**
 * @fileoverview Common enums.
 */

import {InvalidArgumentsException} from '../exception/invalid_arguments_exception';

import * as Bytes from './bytes';

/**
 * Supported elliptic curves.
 */
export enum CurveType {
  P256 = 1,
  P384,
  P521
}

/**
 * Supported point format.
 */
export enum PointFormatType {
  UNCOMPRESSED = 1,
  COMPRESSED,

  // Like UNCOMPRESSED but without the \x04 prefix. Crunchy uses this format.
  // DO NOT USE unless you are a Crunchy user moving to Tink.
  DO_NOT_USE_CRUNCHY_UNCOMPRESSED
}

/**
 * Supported ECDSA signature encoding.
 */
export enum EcdsaSignatureEncodingType {

  // The DER signature is encoded using ASN.1
  // (https://tools.ietf.org/html/rfc5480#appendix-A):
  // ECDSA-Sig-Value :: = SEQUENCE { r INTEGER, s INTEGER }. In particular, the
  // encoding is:
  // 0x30 || totalLength || 0x02 || r's length || r || 0x02 || s's length || s.
  DER = 1,

  // The IEEE_P1363 signature's format is r || s, where r and s are zero-padded
  // and have the same size in bytes as the order of the curve. For example, for
  // NIST P-256 curve, r and s are zero-padded to 32 bytes.
  IEEE_P1363
}

/**
 * Transform an ECDSA signature in DER encoding to IEEE P1363 encoding.
 *
 * @param der the ECDSA signature in DER encoding
 * @param ieeeLength the length of the ECDSA signature in IEEE
 *     encoding. This is usually 2 * size of the elliptic curve field.
 * @return ECDSA signature in IEEE encoding
 */
export function ecdsaDer2Ieee(der: Uint8Array, ieeeLength: number): Uint8Array {
  if (!isValidDerEcdsaSignature(der)) {
    throw new InvalidArgumentsException('invalid DER signature');
  }
  if (!Number.isInteger(ieeeLength) || ieeeLength < 0) {
    throw new InvalidArgumentsException(
        'ieeeLength must be a nonnegative integer');
  }
  const ieee = new Uint8Array(ieeeLength);
  const length = der[1] & 255;
  let offset = 1 +
      /* 0x30 */
      1;

  /* totalLength */
  if (length >= 128) {
    offset++;
  }

  // Long form length
  offset++;

  // 0x02
  const rLength = der[offset++];
  let extraZero = 0;
  if (der[offset] === 0) {
    extraZero = 1;
  }
  const rOffset = ieeeLength / 2 - rLength + extraZero;
  ieee.set(der.subarray(offset + extraZero, offset + rLength), rOffset);
  offset += rLength +
      /* r byte array */
      1;

  /* 0x02 */
  const sLength = der[offset++];
  extraZero = 0;
  if (der[offset] === 0) {
    extraZero = 1;
  }
  const sOffset = ieeeLength - sLength + extraZero;
  ieee.set(der.subarray(offset + extraZero, offset + sLength), sOffset);
  return ieee;
}

/**
 * Transform an ECDSA signature in IEEE 1363 encoding to DER encoding.
 *
 * @param ieee the ECDSA signature in IEEE encoding
 * @return ECDSA signature in DER encoding
 */
export function ecdsaIeee2Der(ieee: Uint8Array): Uint8Array {
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
    der[offset++] = 48;
    der[offset++] = 128 + 1;
    der[offset++] = length;
  } else {
    der = new Uint8Array(length + 2);
    der[offset++] = 48;
    der[offset++] = length;
  }
  der[offset++] = 2;
  der[offset++] = r.length;
  der.set(r, offset);
  offset += r.length;
  der[offset++] = 2;
  der[offset++] = s.length;
  der.set(s, offset);
  return der;
}

/**
 * Validate that the ECDSA signature is in DER encoding, based on
 * https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki.
 *
 * @param sig an ECDSA siganture
 */
export function isValidDerEcdsaSignature(sig: Uint8Array): boolean {
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
  /* S */
  if (sig.length < 1 +
          /* 0x30 */
          1 +
          /* total-length */
          1 +
          /* 0x02 */
          1 +
          /* R-length */
          1 +
          /* R */
          1 +
          /* 0x02 */
          1 +
          /* S-length */
          1) {
    // Signature is too short.
    return false;
  }

  // Checking bytes from left to right.

  // byte #1: a signature is of type 0x30 (compound).
  if (sig[0] != 48) {
    return false;
  }

  // byte #2 and maybe #3: the total length of the signature.
  let totalLen = sig[1] & 255;
  let totalLenLen = 1;

  // the length of the total length field, could be 2-byte.
  if (totalLen == 129) {
    // The signature is >= 128 bytes thus total length field is in long-form
    // encoding and occupies 2 bytes.
    totalLenLen = 2;

    // byte #3 is the total length.
    totalLen = sig[2] & 255;
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
  if (sig[1 + totalLenLen] != 2) {
    return false;
  }

  // Extract the length of the R element.
  const rLen = sig[1 +
                   /* 0x30 */
                   totalLenLen + 1] &
      /* 0x02 */
      255;

  // Make sure the length of the S element is still inside the signature.
  if (1 +
          /* 0x30 */
          totalLenLen + 1 +
          /* 0x02 */
          1 +
          /* rLen */
          rLen + 1 >=
      /* 0x02 */
      sig.length) {
    return false;
  }

  // Zero-length integers are not allowed for R.
  if (rLen == 0) {
    return false;
  }

  // Negative numbers are not allowed for R.
  if ((sig[3 + totalLenLen] & 255) >= 128) {
    return false;
  }

  // Null bytes at the start of R are not allowed, unless R would
  // otherwise be interpreted as a negative number.
  if (rLen > 1 && sig[3 + totalLenLen] == 0 &&
      (sig[4 + totalLenLen] & 255) < 128) {
    return false;
  }

  // Start checking S.
  // Check whether the S element is an integer.
  if (sig[3 + totalLenLen + rLen] != 2) {
    return false;
  }

  // Extract the length of the S element.
  const sLen = sig[1 +
                   /* 0x30 */
                   totalLenLen + 1 +
                   /* 0x02 */
                   1 +
                   /* rLen */
                   rLen + 1] &
      /* 0x02 */
      255;

  // Verify that the length of the signature matches the sum of the length of
  // the elements.
  if (1 +
          /* 0x30 */
          totalLenLen + 1 +
          /* 0x02 */
          1 +
          /* rLen */
          rLen + 1 +
          /* 0x02 */
          1 +
          /* sLen */
          sLen !=
      sig.length) {
    return false;
  }

  // Zero-length integers are not allowed for S.
  if (sLen == 0) {
    return false;
  }

  // Negative numbers are not allowed for S.
  if ((sig[5 + totalLenLen + rLen] & 255) >= 128) {
    return false;
  }

  // Null bytes at the start of S are not allowed, unless S would
  // otherwise be interpreted as a negative number.
  if (sLen > 1 && sig[5 + totalLenLen + rLen] == 0 &&
      (sig[6 + totalLenLen + rLen] & 255) < 128) {
    return false;
  }
  return true;
}

/**
 * Transform a big integer in big endian to minimal unsigned form which has
 * no extra zero at the beginning except when the highest bit is set.
 *
 */
function toUnsignedBigNum(bytes: Uint8Array): Uint8Array {
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
  if ((bytes[start] & 128) == 128) {
    // Add extra zero.
    extraZero = 1;
  }
  const res = new Uint8Array(bytes.length - start + extraZero);
  res.set(bytes.subarray(start), extraZero);
  return res;
}

export function curveToString(curve: CurveType): string {
  switch (curve) {
    case CurveType.P256:
      return 'P-256';
    case CurveType.P384:
      return 'P-384';
    case CurveType.P521:
      return 'P-521';
  }
}

export function curveFromString(curve: string): CurveType {
  switch (curve) {
    case 'P-256':
      return CurveType.P256;
    case 'P-384':
      return CurveType.P384;
    case 'P-521':
      return CurveType.P521;
  }
  throw new InvalidArgumentsException('unknown curve: ' + curve);
}

export function pointEncode(
    curve: string, format: PointFormatType, point: JsonWebKey): Uint8Array {
  const fieldSize = fieldSizeInBytes(curveFromString(curve));
  switch (format) {
    case PointFormatType.UNCOMPRESSED: {
      const {x, y} = point;
      if (x === undefined) {
        throw new InvalidArgumentsException('x must be provided');
      }
      if (y === undefined) {
        throw new InvalidArgumentsException('y must be provided');
      }
      const result = new Uint8Array(1 + 2 * fieldSize);
      result[0] = 4;
      result.set(
          /* opt_webSafe = */
          Bytes.fromBase64(x, true), 1);
      result.set(
          /* opt_webSafe = */
          Bytes.fromBase64(y, true), 1 + fieldSize);
      return result;
    }
    case PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      const {x, y} = point;
      if (x === undefined) {
        throw new InvalidArgumentsException('x must be provided');
      }
      if (y === undefined) {
        throw new InvalidArgumentsException('y must be provided');
      }
      let decodedX = Bytes.fromBase64(x, /* opt_webSafe = */ true);
      let decodedY = Bytes.fromBase64(y, /* opt_webSafe = */ true);
      if (decodedX.length > fieldSize) {
        // x has leading 0's, strip them.
        decodedX = decodedX.slice(decodedX.length - fieldSize, decodedX.length);
      }
      if (decodedY.length > fieldSize) {
        // y has leading 0's, strip them.
        decodedY = decodedY.slice(decodedY.length - fieldSize, decodedY.length);
      }
      const result = new Uint8Array(2 * fieldSize);
      result.set(decodedX, 0);
      result.set(decodedY, fieldSize);
      return result;
    }
    default:
      throw new InvalidArgumentsException('invalid format');
  }
}

export function pointDecode(
    curve: string, format: PointFormatType, point: Uint8Array): JsonWebKey {
  const fieldSize = fieldSizeInBytes(curveFromString(curve));
  switch (format) {
    case PointFormatType.UNCOMPRESSED: {
      if (point.length !== 1 + 2 * fieldSize || point[0] !== 4) {
        throw new InvalidArgumentsException('invalid point');
      }
      const result = ({
        'kty': 'EC',
        'crv': curve,
        'x': Bytes.toBase64(
            new Uint8Array(point.subarray(1, 1 + fieldSize)),
            /* websafe */
            true),
        'y': Bytes.toBase64(
            new Uint8Array(point.subarray(1 + fieldSize, point.length)),
            /* websafe */
            true),
        'ext': true
      } as JsonWebKey);
      return result;
    }
    case PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      if (point.length !== 2 * fieldSize) {
        throw new InvalidArgumentsException('invalid point');
      }
      const result = ({
        'kty': 'EC',
        'crv': curve,
        'x': Bytes.toBase64(
            new Uint8Array(point.subarray(0, fieldSize)), /* websafe */ true),
        'y': Bytes.toBase64(
            new Uint8Array(point.subarray(fieldSize, point.length)),
            /* websafe */ true),
        'ext': true
      } as JsonWebKey);
      return result;
    }
    default:
      throw new InvalidArgumentsException('invalid format');
  }
}

export function getJsonWebKey(
    curve: CurveType, x: Uint8Array, y: Uint8Array,
    d?: Uint8Array|null): JsonWebKey {
  const key = ({
    'kty': 'EC',
    'crv': curveToString(curve),
    'x': Bytes.toBase64(
        x,
        /* websafe */
        true),
    'y': Bytes.toBase64(
        y,
        /* websafe */
        true),
    'ext': true
  } as JsonWebKey);
  if (d) {
    key['d'] = Bytes.toBase64(
        d,
        /* websafe */
        true);
  }
  return key;
}

export function fieldSizeInBytes(curve: CurveType): number {
  switch (curve) {
    case CurveType.P256:
      return 32;
    case CurveType.P384:
      return 48;
    case CurveType.P521:
      return 66;
  }
}

export function encodingSizeInBytes(
    curve: CurveType, pointFormat: PointFormatType): number {
  switch (pointFormat) {
    case PointFormatType.UNCOMPRESSED:
      return 2 * fieldSizeInBytes(curve) + 1;
    case PointFormatType.COMPRESSED:
      return fieldSizeInBytes(curve) + 1;
    case PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
      return 2 * fieldSizeInBytes(curve);
  }
}

export async function computeEcdhSharedSecret(
    privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  const {namedCurve}: Partial<EcKeyImportParams> = privateKey.algorithm;
  if (!namedCurve) {
    throw new InvalidArgumentsException('namedCurve must be provided');
  }
  const ecdhParams = {'public': publicKey, ...privateKey.algorithm};
  const fieldSizeInBits = 8 * fieldSizeInBytes(curveFromString(namedCurve));
  const sharedSecret = await window.crypto.subtle.deriveBits(
      ecdhParams, privateKey, fieldSizeInBits);
  return new Uint8Array(sharedSecret);
}

export async function generateKeyPair(
    algorithm: 'ECDH'|'ECDSA', curve: string): Promise<CryptoKeyPair> {
  if (algorithm != 'ECDH' && algorithm != 'ECDSA') {
    throw new InvalidArgumentsException(
        'algorithm must be either ECDH or ECDSA');
  }
  const params = {'name': algorithm, 'namedCurve': curve};
  const ephemeralKeyPair = await window.crypto.subtle.generateKey(
      params, /* extractable= */ true,
      algorithm == 'ECDH' ? ['deriveKey', 'deriveBits'] : ['sign', 'verify']);
  return ephemeralKeyPair as CryptoKeyPair;
}

export async function exportCryptoKey(cryptoKey: CryptoKey):
    Promise<JsonWebKey> {
  const jwk = await window.crypto.subtle.exportKey('jwk', cryptoKey);
  return (jwk);
}

export async function importPublicKey(
    algorithm: string, jwk: JsonWebKey): Promise<CryptoKey> {
  if (algorithm != 'ECDH' && algorithm != 'ECDSA') {
    throw new InvalidArgumentsException(
        'algorithm must be either ECDH or ECDSA');
  }
  const {crv} = jwk;
  if (!crv) {
    throw new InvalidArgumentsException('crv must be provided');
  }
  const publicKey = await window.crypto.subtle.importKey(
      /* format */
      'jwk', jwk, {'name': algorithm, 'namedCurve': crv},
      /* algorithm */
      true,
      /* extractable */
      algorithm == 'ECDH' ? [] : ['verify']);

  /* usage */
  return publicKey;
}

export async function importPrivateKey(
    algorithm: string, jwk: JsonWebKey): Promise<CryptoKey> {
  if (algorithm != 'ECDH' && algorithm != 'ECDSA') {
    throw new InvalidArgumentsException(
        'algorithm must be either ECDH or ECDSA');
  }
  const {crv} = jwk;
  if (!crv) {
    throw new InvalidArgumentsException('crv must be provided');
  }
  const privateKey = await window.crypto.subtle.importKey(
      /* format */
      'jwk', jwk,
      /* key material */
      {'name': algorithm, 'namedCurve': crv},
      /* algorithm */
      true,
      /* extractable */
      algorithm == 'ECDH' ? ['deriveKey', 'deriveBits'] : ['sign']);

  /* usage */
  return privateKey;
}
