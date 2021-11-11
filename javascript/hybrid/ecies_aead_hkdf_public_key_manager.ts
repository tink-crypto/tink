/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as KeyManager from '../internal/key_manager';
import {PbEciesAeadHkdfParams, PbEciesAeadHkdfPublicKey, PbKeyData, PbKeyTemplate, PbMessage} from '../internal/proto';
import * as Util from '../internal/util';
import * as eciesAeadHkdfHybridEncrypt from '../subtle/ecies_aead_hkdf_hybrid_encrypt';

import * as EciesAeadHkdfUtil from './ecies_aead_hkdf_util';
import * as EciesAeadHkdfValidators from './ecies_aead_hkdf_validators';
import {HybridEncrypt} from './internal/hybrid_encrypt';
import {RegistryEciesAeadHkdfDemHelper} from './registry_ecies_aead_hkdf_dem_helper';

/**
 * @final
 */
class EciesAeadHkdfPublicKeyFactory implements KeyManager.KeyFactory {
  newKey(keyFormat: PbMessage|Uint8Array): never {
    throw new SecurityException(
        'This operation is not supported for public keys. ' +
        'Use EciesAeadHkdfPrivateKeyManager to generate new keys.');
  }

  newKeyData(serializedKeyFormat: Uint8Array): never {
    throw new SecurityException(
        'This operation is not supported for public keys. ' +
        'Use EciesAeadHkdfPrivateKeyManager to generate new keys.');
  }
}

/**
 * @final
 */
export class EciesAeadHkdfPublicKeyManager implements
    KeyManager.KeyManager<HybridEncrypt> {
  static KEY_TYPE: string =
      'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
  private static readonly SUPPORTED_PRIMITIVE = HybridEncrypt;
  static VERSION: number = 0;
  keyFactory = new EciesAeadHkdfPublicKeyFactory();

  async getPrimitive(
      primitiveType: Util.Constructor<HybridEncrypt>,
      key: PbKeyData|PbMessage) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    const keyProto = EciesAeadHkdfPublicKeyManager.getKeyProto(key);
    EciesAeadHkdfValidators.validatePublicKey(keyProto, this.getVersion());
    const recepientPublicKey =
        EciesAeadHkdfUtil.getJsonWebKeyFromProto(keyProto);
    const params = (keyProto.getParams() as PbEciesAeadHkdfParams);
    const demParams = params.getDemParams();
    if (!demParams) {
      throw new SecurityException('DEM params not set');
    }
    const keyTemplate = (demParams.getAeadDem() as PbKeyTemplate);
    const demHelper = new RegistryEciesAeadHkdfDemHelper(keyTemplate);
    const pointFormat =
        Util.pointFormatProtoToSubtle(params.getEcPointFormat());
    const kemParams = params.getKemParams();
    if (!kemParams) {
      throw new SecurityException('KEM params not set');
    }
    const hkdfHash = Util.hashTypeProtoToString(kemParams.getHkdfHashType());
    const hkdfSalt = kemParams.getHkdfSalt_asU8();
    return eciesAeadHkdfHybridEncrypt.fromJsonWebKey(
        recepientPublicKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return EciesAeadHkdfPublicKeyManager.KEY_TYPE;
  }

  getPrimitiveType() {
    return EciesAeadHkdfPublicKeyManager.SUPPORTED_PRIMITIVE;
  }

  getVersion() {
    return EciesAeadHkdfPublicKeyManager.VERSION;
  }

  getKeyFactory() {
    return this.keyFactory;
  }

  private static getKeyProto(keyMaterial: PbKeyData|
                             PbMessage): PbEciesAeadHkdfPublicKey {
    if (keyMaterial instanceof PbKeyData) {
      return EciesAeadHkdfPublicKeyManager.getKeyProtoFromKeyData(keyMaterial);
    }
    if (keyMaterial instanceof PbEciesAeadHkdfPublicKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key manager supports ' +
        EciesAeadHkdfPublicKeyManager.KEY_TYPE + '.');
  }

  private static getKeyProtoFromKeyData(keyData: PbKeyData):
      PbEciesAeadHkdfPublicKey {
    if (keyData.getTypeUrl() !== EciesAeadHkdfPublicKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() + ' is not supported. This key ' +
          'manager supports ' + EciesAeadHkdfPublicKeyManager.KEY_TYPE + '.');
    }
    let key: PbEciesAeadHkdfPublicKey;
    try {
      key = PbEciesAeadHkdfPublicKey.deserializeBinary(keyData.getValue());
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' +
          EciesAeadHkdfPublicKeyManager.KEY_TYPE + ' key-proto.');
    }
    if (!key.getParams() || !key.getX() || !key.getY()) {
      throw new SecurityException(
          'Input cannot be parsed as ' +
          EciesAeadHkdfPublicKeyManager.KEY_TYPE + ' key-proto.');
    }
    return key;
  }
}
