/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../../../exception/security_exception';
import {PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeKeyFormat, PbHpkeParams, PbHpkePrivateKey, PbHpkePublicKey} from '../../../internal/proto';
import {bytesLength} from '../../../internal/proto_shims';
import * as validators from '../../../subtle/validators';

/** Validate HPKE params. */
export function validateParams(params: PbHpkeParams) {
  const kem: PbHpkeKem = params.getKem();
  if (kem !== PbHpkeKem.DHKEM_P256_HKDF_SHA256 &&
      kem !== PbHpkeKem.DHKEM_P521_HKDF_SHA512) {
    throw new SecurityException(
        'Invalid hpke params - unknown KEM identifier.');
  }

  const kdf: PbHpkeKdf = params.getKdf();
  if (kdf !== PbHpkeKdf.HKDF_SHA256 && kdf !== PbHpkeKdf.HKDF_SHA512) {
    throw new SecurityException(
        'Invalid hpke params - unknown KDF identifier.');
  }

  const aead: PbHpkeAead = params.getAead();
  if (aead !== PbHpkeAead.AES_128_GCM && aead !== PbHpkeAead.AES_256_GCM) {
    throw new SecurityException(
        'Invalid hpke params - unknown AEAD identifier.');
  }
}

/** Validate HPKE key format. */
export function validateKeyFormat(keyFormat: PbHpkeKeyFormat) {
  const params: PbHpkeParams|undefined = keyFormat.getParams();
  if (!params) {
    throw new SecurityException('Invalid key format - missing key params.');
  }
  validateParams(params);
}

/** Validate HPKE public key. */
export function validatePublicKey(
    key: PbHpkePublicKey, publicKeyManagerVersion: number) {
  validators.validateVersion(key.getVersion(), publicKeyManagerVersion);
  const params: PbHpkeParams|undefined = key.getParams();
  if (!params) {
    throw new SecurityException('Invalid public key - missing key params.');
  }
  validateParams(params);
  if (bytesLength(key.getPublicKey()) === 0) {
    throw new SecurityException(
        'Invalid public key - missing public key value.');
  }
}

/** Validate HPKE private key. */
export function validatePrivateKey(
    key: PbHpkePrivateKey, privateKeyManagerVersion: number,
    publicKeyManagerVersion: number) {
  validators.validateVersion(key.getVersion(), privateKeyManagerVersion);
  if (bytesLength(key.getPrivateKey()) === 0) {
    throw new SecurityException(
        'Invalid private key - missing private key value.');
  }
  const publicKey: PbHpkePublicKey|undefined = key.getPublicKey();
  if (!publicKey) {
    throw new SecurityException(
        'Invalid private key - missing public key field.');
  }
  validatePublicKey(publicKey, publicKeyManagerVersion);
}
