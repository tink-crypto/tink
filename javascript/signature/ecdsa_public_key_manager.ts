/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as KeyManager from '../internal/key_manager';
import {PbEcdsaParams, PbEcdsaPublicKey, PbKeyData, PbMessage} from '../internal/proto';
import * as Util from '../internal/util';
import * as ecdsaVerify from '../subtle/ecdsa_verify';

import * as EcdsaUtil from './ecdsa_util';
import {PublicKeyVerify} from './internal/public_key_verify';

/**
 * @final
 */
class EcdsaPublicKeyFactory implements KeyManager.KeyFactory {
  newKey(keyFormat: PbMessage|Uint8Array): never {
    throw new SecurityException(
        'This operation is not supported for public keys. ' +
        'Use EcdsaPrivateKeyManager to generate new keys.');
  }

  newKeyData(serializedKeyFormat: Uint8Array): never {
    throw new SecurityException(
        'This operation is not supported for public keys. ' +
        'Use EcdsaPrivateKeyManager to generate new keys.');
  }
}

/**
 * @final
 */
export class EcdsaPublicKeyManager implements
    KeyManager.KeyManager<PublicKeyVerify> {
  static KEY_TYPE: string =
      'type.googleapis.com/google.crypto.tink.EcdsaPublicKey';
  private static readonly SUPPORTED_PRIMITIVE = PublicKeyVerify;
  static VERSION: number = 0;
  keyFactory = new EcdsaPublicKeyFactory();

  async getPrimitive(
      primitiveType: Util.Constructor<PublicKeyVerify>,
      key: PbKeyData|PbMessage) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    const keyProto = EcdsaPublicKeyManager.getKeyProto(key);
    EcdsaUtil.validatePublicKey(keyProto, this.getVersion());
    const jwk = EcdsaUtil.getJsonWebKeyFromProto(keyProto);
    const params = (keyProto.getParams() as PbEcdsaParams);
    const hash = Util.hashTypeProtoToString(params.getHashType());
    const encoding = EcdsaUtil.encodingTypeProtoToEnum(params.getEncoding());
    return ecdsaVerify.fromJsonWebKey(jwk, hash, encoding);
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return EcdsaPublicKeyManager.KEY_TYPE;
  }

  getPrimitiveType() {
    return EcdsaPublicKeyManager.SUPPORTED_PRIMITIVE;
  }

  getVersion() {
    return EcdsaPublicKeyManager.VERSION;
  }

  getKeyFactory() {
    return this.keyFactory;
  }

  private static getKeyProto(keyMaterial: PbKeyData|
                             PbMessage): PbEcdsaPublicKey {
    if (keyMaterial instanceof PbKeyData) {
      return EcdsaPublicKeyManager.getKeyProtoFromKeyData(keyMaterial);
    }
    if (keyMaterial instanceof PbEcdsaPublicKey) {
      return keyMaterial;
    }
    throw new SecurityException(
        'Key type is not supported. This key manager supports ' +
        EcdsaPublicKeyManager.KEY_TYPE + '.');
  }

  private static getKeyProtoFromKeyData(keyData: PbKeyData): PbEcdsaPublicKey {
    if (keyData.getTypeUrl() !== EcdsaPublicKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() + ' is not supported. This key ' +
          'manager supports ' + EcdsaPublicKeyManager.KEY_TYPE + '.');
    }
    let key: PbEcdsaPublicKey;
    try {
      key = PbEcdsaPublicKey.deserializeBinary(keyData.getValue());
    } catch (e) {
      throw new SecurityException(
          'Input cannot be parsed as ' + EcdsaPublicKeyManager.KEY_TYPE +
          ' key-proto.');
    }
    if (!key.getParams() || !key.getX() || !key.getY()) {
      throw new SecurityException(
          'Input cannot be parsed as ' + EcdsaPublicKeyManager.KEY_TYPE +
          ' key-proto.');
    }
    return key;
  }
}
