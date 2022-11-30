/**
 * @license
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import * as ellipticCurves from '../../../subtle/elliptic_curves';

import {HpkeKemPrivateKey} from './hpke_kem_private_key';
import * as hpkeUtil from './hpke_util';

/**
 * Private keys used in Diffie-Hellman-based P256 and P521 HPKE KEM
 * variants.
 */
export class NistCurvesHpkeKemPrivateKey implements HpkeKemPrivateKey {
  constructor(readonly privateKey: CryptoKey, readonly publicKey: CryptoKey) {}

  async getSerializedPublicKey(): Promise<Uint8Array> {
    return await hpkeUtil.getByteArrayFromPublicKey(this.publicKey);
  }
}

/**
 * Converts an uncompressed point encoded `publicKey` and its associated
 * `privateKey` into a `NistCurvesHpkeKemPrivateKey`.
 */
export async function fromBytes({privateKey, publicKey, curveType}: {
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  curveType: ellipticCurves.CurveType.P256|ellipticCurves.CurveType.P521
}): Promise<NistCurvesHpkeKemPrivateKey> {
  if (!privateKey) {
    throw new InvalidArgumentsException(
        'KEM private key was null or undefined');
  }
  if (!publicKey) {
    throw new InvalidArgumentsException('KEM public key was null or undefined');
  }
  const publicCryptoKey = await hpkeUtil.getPublicKeyFromByteArray(
      ellipticCurves.curveToString(curveType), publicKey);

  const privateCryptoKey = await hpkeUtil.getPrivateKeyFromByteArray({
    curveType: ellipticCurves.curveToString(curveType),
    publicKey,
    privateKey
  });

  return new NistCurvesHpkeKemPrivateKey(privateCryptoKey, publicCryptoKey);
}

/**
 * Converts a `CryptoKeyPair` into a `NistCurvesHpkeKemPrivateKey`. The
 * algorithm on both keys must be ECDH and both keys should be valid.
 */
export async function fromCryptoKeyPair(keyPair: CryptoKeyPair):
    Promise<NistCurvesHpkeKemPrivateKey> {
  validateECDHCryptoKey(keyPair.privateKey, 'private');
  validateECDHCryptoKey(keyPair.publicKey, 'public');
  return new NistCurvesHpkeKemPrivateKey(keyPair.privateKey, keyPair.publicKey);
}

function validateECDHCryptoKey(key: CryptoKey, type: 'public'|'private') {
  if (type !== key.type) {
    throw new InvalidArgumentsException(
        `keyPair ${type} key was of type ${key.type}`);
  }
  const alg: EcKeyGenParams = key.algorithm as EcKeyGenParams;

  if ('ECDH' !== alg.name) {
    throw new InvalidArgumentsException(
        `keyPair ${type} key should be ECDH but found ${alg.name}`);
  }
}
