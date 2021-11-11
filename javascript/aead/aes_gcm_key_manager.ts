/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as KeyManager from '../internal/key_manager';
import {PbAesGcmKey, PbAesGcmKeyFormat, PbKeyData, PbMessage} from '../internal/proto';
import * as Registry from '../internal/registry';
import {Constructor} from '../internal/util';
import * as aesGcm from '../subtle/aes_gcm';
import * as Random from '../subtle/random';
import * as Validators from '../subtle/validators';

import {Aead} from './internal/aead';

const VERSION = 0;

/**
 * @final
 */
class AesGcmKeyFactory implements KeyManager.KeyFactory {
  newKey(keyFormat: PbMessage|Uint8Array) {
    const keyFormatProto = AesGcmKeyFactory.getKeyFormatProto(keyFormat);
    AesGcmKeyFactory.validateKeyFormat(keyFormatProto);
    const key = (new PbAesGcmKey())
                    .setKeyValue(Random.randBytes(keyFormatProto.getKeySize()))
                    .setVersion(VERSION);
    return key;
  }

  newKeyData(serializedKeyFormat: Uint8Array) {
    const key = (this.newKey(serializedKeyFormat));
    const keyData =
        (new PbKeyData())
            .setTypeUrl(AesGcmKeyManager.KEY_TYPE)
            .setValue(key.serializeBinary())
            .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
    return keyData;
  }

  private static validateKeyFormat(keyFormat: PbAesGcmKeyFormat) {
    Validators.validateAesKeySize(keyFormat.getKeySize());
  }

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an AesGcmKeyFormat-proto (otherwise).
   *
   */
  private static getKeyFormatProto(keyFormat: PbMessage|
                                   Uint8Array): PbAesGcmKeyFormat {
    if (keyFormat instanceof Uint8Array) {
      return AesGcmKeyFactory.deserializeKeyFormat(keyFormat);
    } else if (keyFormat instanceof PbAesGcmKeyFormat) {
      return keyFormat;
    } else {
      throw new SecurityException('Expected AesGcmKeyFormat-proto');
    }
  }

  private static deserializeKeyFormat(keyFormat: Uint8Array):
      PbAesGcmKeyFormat {
    let keyFormatProto: PbAesGcmKeyFormat;
    try {
      keyFormatProto = PbAesGcmKeyFormat.deserializeBinary(keyFormat);
    } catch (e) {
      throw new SecurityException(
          'Could not parse the input as a serialized proto of ' +
          AesGcmKeyManager.KEY_TYPE + ' key format.');
    }
    if (!keyFormatProto.getKeySize()) {
      throw new SecurityException(
          'Could not parse the input as a serialized proto of ' +
          AesGcmKeyManager.KEY_TYPE + ' key format.');
    }
    return keyFormatProto;
  }
}

/**
 * @final
 */
export class AesGcmKeyManager implements KeyManager.KeyManager<Aead> {
  private static readonly SUPPORTED_PRIMITIVE = Aead;
  static KEY_TYPE: string = 'type.googleapis.com/google.crypto.tink.AesGcmKey';
  private readonly keyFactory: AesGcmKeyFactory;

  /** Visible for testing. */
  constructor() {
    this.keyFactory = new AesGcmKeyFactory();
  }

  async getPrimitive(
      primitiveType: Constructor<Aead>, key: PbKeyData|PbMessage) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    const keyProto = AesGcmKeyManager.getKeyProto(key);
    AesGcmKeyManager.validateKey(keyProto);
    return await aesGcm.fromRawKey(keyProto.getKeyValue_asU8());
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return AesGcmKeyManager.KEY_TYPE;
  }

  getPrimitiveType() {
    return AesGcmKeyManager.SUPPORTED_PRIMITIVE;
  }

  getVersion() {
    return VERSION;
  }

  getKeyFactory() {
    return this.keyFactory;
  }

  private static validateKey(key: PbAesGcmKey) {
    Validators.validateAesKeySize(key.getKeyValue().length);
    Validators.validateVersion(key.getVersion(), VERSION);
  }

  /**
   * The input key is either deserialized (in case that the input is
   * KeyData-proto) or checked to be an AesGcmKey-proto (otherwise).
   *
   */
  private static getKeyProto(keyMaterial: PbMessage|PbKeyData): PbAesGcmKey {
    if (keyMaterial instanceof PbKeyData) {
      return AesGcmKeyManager.getKeyProtoFromKeyData(keyMaterial);
    } else if (keyMaterial instanceof PbAesGcmKey) {
      return keyMaterial;
    } else {
      throw new SecurityException(
          'Key type is not supported. ' +
          'This key manager supports ' + AesGcmKeyManager.KEY_TYPE + '.');
    }
  }

  /**
   * It validates the key type and returns a deserialized AesGcmKey-proto.
   *
   */
  private static getKeyProtoFromKeyData(keyData: PbKeyData): PbAesGcmKey {
    if (keyData.getTypeUrl() != AesGcmKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() +
          ' is not supported. This key manager supports ' +
          AesGcmKeyManager.KEY_TYPE + '.');
    }
    let deserializedKey: PbAesGcmKey;
    try {
      deserializedKey = PbAesGcmKey.deserializeBinary(keyData.getValue());
    } catch (e) {
      throw new SecurityException(
          'Could not parse the input as a ' +
          'serialized proto of ' + AesGcmKeyManager.KEY_TYPE + ' key.');
    }
    if (!deserializedKey.getKeyValue()) {
      throw new SecurityException(
          'Could not parse the input as a ' +
          'serialized proto of ' + AesGcmKeyManager.KEY_TYPE + ' key.');
    }
    return deserializedKey;
  }

  static register() {
    Registry.registerKeyManager(new AesGcmKeyManager());
  }
}
