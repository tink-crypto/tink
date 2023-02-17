/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {SecurityException} from '../../../exception/security_exception';
import {PbHpkeKem} from '../../../internal/proto';
import * as bytes from '../../../subtle/bytes';
import * as ellipticCurves from '../../../subtle/elliptic_curves';

/** HPKE mode identifiers. */
export const BASE_MODE = numberToByteArray(1, 0x00);

/** HPKE KEM algorithm identifier for P256 HKDF SHA256 KEM */
export const P256_HKDF_SHA256_KEM_ID = numberToByteArray(2, 0x0010);

/** HPKE KEM algorithm identifier for P521 HKDF SHA512 KEM */
export const P521_HKDF_SHA512_KEM_ID = numberToByteArray(2, 0x0012);

/** HPKE KDF algorithm identifier for HKDF SHA256 KDF */
export const HKDF_SHA256_KDF_ID = numberToByteArray(2, 0x0001);

/** HPKE KDF algorithm identifier for HKDF SHA512 KDF */
export const HKDF_SHA512_KDF_ID = numberToByteArray(2, 0x0003);

/** HPKE AEAD algorithm identifier for AES128 GCM */
export const AES_128_GCM_AEAD_ID = numberToByteArray(2, 0x0001);
/** HPKE AEAD algorithm identifier for AES256 GCM */
export const AES_256_GCM_AEAD_ID = numberToByteArray(2, 0x0002);

/** HPKE byte array representation for KEM */
export const KEM = bytes.fromByteString('KEM');
/** HPKE byte array representation for KPKE */
export const HPKE = bytes.fromByteString('HPKE');
/** HPKE byte array representation for HPKE-v1 */
export const HPKE_V1 = bytes.fromByteString('HPKE-v1');

/**
 * Transforms a passed value to an MSB first byte array with the size of the
 * specified capacity.
 *
 * The HPKE standard defines this function as I2OSP(n, w) where w =
 * capacity and n = value.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#name-notation
 */
export function numberToByteArray(capacity: number, value: number): Uint8Array {
  const result = new Uint8Array(capacity);
  for (let i = 0; i < capacity; i++) {
    result[i] = (value >> (8 * (capacity - i - 1))) & 0xFF;
  }
  return result;
}


/**
 * Transforms `value` to a MSB-first byte array of size `capacity`.
 *
 * The HPKE standard defines this function as I2OSP(n, w) where w =
 * capacity and n = value.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#name-notation
 *
 */
export function bigIntToByteArray(capacity: number, value: bigint): Uint8Array {
  const result = new Uint8Array(capacity);
  for (let i = 0; i < capacity; i++) {
    result[i] = Number((value >> BigInt((8 * (capacity - i - 1))))) & 0xFF;
  }
  return result;
}

/**
 * Generates KEM suite id from `kemId` according to the definition in
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1-5. Only used for
 * KEM suite id.
 * @throws SecurityException if byte concatenation fails.
 */
export function kemSuiteId(kemId: Uint8Array): Uint8Array {
  return bytes.concat(KEM, kemId);
}

/**
 * Generates HPKE suite id from `kemId`, `kdfId`, and `aeadId` according to the
 * definition in @see https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-8.
 * Used for any non-KEM suite id.
 * @throws a SecurityException if byte concatenation fails.
 */
export function hpkeSuiteId(
    {kemId, kdfId, aeadId}:
        {kemId: Uint8Array, kdfId: Uint8Array, aeadId: Uint8Array}):
    Uint8Array {
  return bytes.concat(HPKE, kemId, kdfId, aeadId);
}

/**
 * Transforms `ikm` into labeled ikm using `label` and `suiteId` according to
 * `LabeledExtract()` defined in
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-4.
 * @throws an SecurityException if byte concatenation fails.
 */
export function labelIkm(
    {ikmLabel, ikm, suiteId}:
        {ikmLabel: string, ikm: Uint8Array, suiteId: Uint8Array}): Uint8Array {
  return bytes.concat(HPKE_V1, suiteId, bytes.fromByteString(ikmLabel), ikm);
}

/**
 * Transforms `info` into labeled info using `label`, `suiteId`, and `length`
 * according to `LabeledExpand()` defined in
 * @see https://www.rfc-editor.org/rfc/rfc9180.html#section-4.
 * @throws a SecurityException if byte concatenation fails.
 */
export function labelInfo({infoLabel, info, suiteId, length}: {
  infoLabel: string,
  info: Uint8Array,
  suiteId: Uint8Array,
  length: number
}): Uint8Array {
  return bytes.concat(
      numberToByteArray(2, length), HPKE_V1, suiteId,
      bytes.fromByteString(infoLabel), info);
}

/** Translates the NIST HPKE KEM identifier to the corresponding curve type */
export function nistHpkeKemToCurve(kem: PbHpkeKem):
    ellipticCurves.CurveType.P256|ellipticCurves.CurveType.P521 {
  switch (kem) {
    case PbHpkeKem.DHKEM_P256_HKDF_SHA256:
      return ellipticCurves.CurveType.P256;
    case PbHpkeKem.DHKEM_P521_HKDF_SHA512:
      return ellipticCurves.CurveType.P521;
    default:
      throw new InvalidArgumentsException(
          'Unrecognized NIST HPKE KEM identifier');
  }
}

/**
 * Performs the uncompressed string (given as `key` in the form of a byte array)
 * to elliptic curve (given via (string) `curveType`) point conversion according
 * to Section 2.3.3 of https://secg.org/sec1-v2.pdf and returns the result as a
 * CryptoKey.
 */
export async function getPublicKeyFromByteArray(
    curveType: string, key: Uint8Array): Promise<CryptoKey> {
  const jsonWebKey = ellipticCurves.pointDecode(
      curveType, ellipticCurves.PointFormatType.UNCOMPRESSED, key);
  return await ellipticCurves.importPublicKey('ECDH', jsonWebKey);
}

/**
 * Converts `{curveType, publicKey, privateKey}`, into a private `CryptoKey`.
 *
 * The `publicKey` is an uncompressed point encoded according to
 * Section 2.3.3 of @see https://secg.org/sec1-v2.pdf. The `privateKey` is a
 * large integer encoded according to Section 2.3.5 of
 * @see https://secg.org/sec1-v2.pdf. `curveType` is the the string
 * representation of the elliptic curve on which to perform the conversion.
 */
export async function getPrivateKeyFromByteArray(
    {curveType, publicKey, privateKey}:
        {curveType: string, publicKey: Uint8Array, privateKey: Uint8Array}):
    Promise<CryptoKey> {
  const jsonWebKey = ellipticCurves.pointDecode(
      curveType, ellipticCurves.PointFormatType.UNCOMPRESSED, publicKey);

  jsonWebKey.d = bytes.toBase64(privateKey, true);

  return await ellipticCurves.importPrivateKey('ECDH', jsonWebKey);
}

/**
 * Converts a public `key` into a `Uint8Array` containing an
 * uncompressed point encoded according to Section 2.3.3 of
 * @see https://secg.org/sec1-v2.pdf.
 */
export async function getByteArrayFromPublicKey(key: CryptoKey):
    Promise<Uint8Array> {
  const alg: EcKeyGenParams = key.algorithm as EcKeyGenParams;
  const jsonWebKey = await ellipticCurves.exportCryptoKey(key);

  if (!jsonWebKey.crv) {
    throw new SecurityException('Curve has to be defined.');
  }

  return ellipticCurves.pointEncode(
      alg.namedCurve, ellipticCurves.PointFormatType.UNCOMPRESSED, jsonWebKey);
}
