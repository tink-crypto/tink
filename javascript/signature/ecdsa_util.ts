/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {PbEcdsaKeyFormat, PbEcdsaParams, PbEcdsaPrivateKey, PbEcdsaPublicKey, PbEcdsaSignatureEncoding as PbEcdsaSignatureEncodingType} from '../internal/proto';
import * as Util from '../internal/util';
import * as EllipticCurves from '../subtle/elliptic_curves';
import * as Validators from '../subtle/validators';

export function validateKeyFormat(keyFormat: PbEcdsaKeyFormat) {
  const params = keyFormat.getParams();
  if (!params) {
    throw new SecurityException('Invalid key format - missing params.');
  }
  validateParams(params);
}

export function validatePrivateKey(
    key: PbEcdsaPrivateKey, privateKeyManagerVersion: number,
    publicKeyManagerVersion: number) {
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
}

export function validatePublicKey(
    key: PbEcdsaPublicKey, publicKeyManagerVersion: number) {
  Validators.validateVersion(key.getVersion(), publicKeyManagerVersion);
  const params = key.getParams();
  if (!params) {
    throw new SecurityException('Invalid public key - missing params.');
  }
  validateParams(params);
  if (!key.getX_asU8().length || !key.getY_asU8().length) {
    throw new SecurityException(
        'Invalid public key - missing value of X or Y.');
  }
}

export function validateParams(params: PbEcdsaParams) {
  if (params.getEncoding() === PbEcdsaSignatureEncodingType.UNKNOWN_ENCODING) {
    throw new SecurityException(
        'Invalid public key - missing signature encoding.');
  }
  const hash = Util.hashTypeProtoToString(params.getHashType());
  const curve = EllipticCurves.curveToString(
      Util.curveTypeProtoToSubtle(params.getCurve()));
  Validators.validateEcdsaParams(curve, hash);
}

export function encodingTypeProtoToEnum(
    encodingTypeProto: PbEcdsaSignatureEncodingType):
    EllipticCurves.EcdsaSignatureEncodingType {
  switch (encodingTypeProto) {
    case PbEcdsaSignatureEncodingType.DER:
      return EllipticCurves.EcdsaSignatureEncodingType.DER;
    case PbEcdsaSignatureEncodingType.IEEE_P1363:
      return EllipticCurves.EcdsaSignatureEncodingType.IEEE_P1363;
    default:
      throw new SecurityException('Unknown ECDSA signature encoding type.');
  }
}

/**
 * WARNING: This method assumes that the given key proto is valid.
 *
 */
export function getJsonWebKeyFromProto(key: PbEcdsaPrivateKey|
                                       PbEcdsaPublicKey): JsonWebKey {
  let publicKey: PbEcdsaPublicKey;
  let d: Uint8Array|null = null;
  if (key instanceof PbEcdsaPrivateKey) {
    publicKey = (key.getPublicKey() as PbEcdsaPublicKey);
  } else {
    publicKey = key;
  }
  const params = publicKey.getParams();
  if (!params) {
    throw new SecurityException('Params not set');
  }
  const curveType = Util.curveTypeProtoToSubtle(params.getCurve());
  const expectedLength = EllipticCurves.fieldSizeInBytes(curveType);
  const x = Util.bigEndianNumberToCorrectLength(
      publicKey.getX_asU8(), expectedLength);
  const y = Util.bigEndianNumberToCorrectLength(
      publicKey.getY_asU8(), expectedLength);
  if (key instanceof PbEcdsaPrivateKey) {
    d = Util.bigEndianNumberToCorrectLength(
        key.getKeyValue_asU8(), expectedLength);
  }
  return EllipticCurves.getJsonWebKey(curveType, x, y, d);
}
