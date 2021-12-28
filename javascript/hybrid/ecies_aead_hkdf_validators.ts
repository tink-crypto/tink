/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../aead/aead_config';
import {SecurityException} from '../exception/security_exception';
import {PbEciesAeadDemParams, PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbPointFormat} from '../internal/proto';
import * as Validators from '../subtle/validators';

function validateKemParams(kemParams: PbEciesHkdfKemParams) {
  const curve = kemParams.getCurveType();
  if (curve !== PbEllipticCurveType.NIST_P256 &&
      curve !== PbEllipticCurveType.NIST_P384 &&
      curve !== PbEllipticCurveType.NIST_P521) {
    throw new SecurityException('Invalid KEM params - unknown curve type.');
  }
  const hashType = kemParams.getHkdfHashType();
  if (hashType !== PbHashType.SHA1 && hashType !== PbHashType.SHA256 &&
      hashType !== PbHashType.SHA384 && hashType !== PbHashType.SHA512) {
    throw new SecurityException('Invalid KEM params - unknown hash type.');
  }
}

function validateDemParams(demParams: PbEciesAeadDemParams) {
  if (!demParams.getAeadDem()) {
    throw new SecurityException(
        'Invalid DEM params - missing AEAD key template.');
  }

  // It is checked also here due to methods for creating new keys. We do not
  // allow creating new keys from formats which contains key templates of
  // not supported key types.
  const aeadKeyType = demParams.getAeadDem()!.getTypeUrl();
  if (aeadKeyType != AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL &&
      aeadKeyType != AeadConfig.AES_GCM_TYPE_URL) {
    throw new SecurityException(
        'Invalid DEM params - ' + aeadKeyType +
        ' template is not supported by ECIES AEAD HKDF.');
  }
}

export function validateParams(params: PbEciesAeadHkdfParams) {
  const kemParams = params.getKemParams();
  if (!kemParams) {
    throw new SecurityException('Invalid params - missing KEM params.');
  }
  validateKemParams(kemParams);
  const demParams = params.getDemParams();
  if (!demParams) {
    throw new SecurityException('Invalid params - missing DEM params.');
  }
  validateDemParams(demParams);
  const pointFormat = params.getEcPointFormat();
  if (pointFormat !== PbPointFormat.UNCOMPRESSED &&
      pointFormat !== PbPointFormat.COMPRESSED &&
      pointFormat !== PbPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED) {
    throw new SecurityException(
        'Invalid key params - unknown EC point format.');
  }
}

export function validateKeyFormat(keyFormat: PbEciesAeadHkdfKeyFormat) {
  const params = keyFormat.getParams();
  if (!params) {
    throw new SecurityException('Invalid key format - missing key params.');
  }
  validateParams(params);
}

export function validatePublicKey(
    key: PbEciesAeadHkdfPublicKey, publicKeyManagerVersion: number) {
  Validators.validateVersion(key.getVersion(), publicKeyManagerVersion);
  const params = key.getParams();
  if (!params) {
    throw new SecurityException('Invalid public key - missing key params.');
  }
  validateParams(params);
  if (!key.getX_asU8().length || !key.getY_asU8().length) {
    throw new SecurityException(
        'Invalid public key - missing value of X or Y.');
  }
}

// TODO Should we add more checks here?
export function validatePrivateKey(
    key: PbEciesAeadHkdfPrivateKey, privateKeyManagerVersion: number,
    publicKeyManagerVersion: number) {
  Validators.validateVersion(key.getVersion(), privateKeyManagerVersion);
  if (!key.getKeyValue_asU8()) {
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

// TODO Should we add more checks here?
