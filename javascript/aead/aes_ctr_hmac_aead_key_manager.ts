/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as KeyManager from '../internal/key_manager';
import {PbAesCtrHmacAeadKey, PbAesCtrHmacAeadKeyFormat, PbAesCtrKey, PbAesCtrKeyFormat, PbAesCtrParams, PbHashType, PbHmacKey, PbHmacKeyFormat, PbHmacParams, PbKeyData, PbMessage} from '../internal/proto';
import * as Registry from '../internal/registry';
import {Constructor} from '../internal/util';
import {aesCtrHmacFromRawKeys} from '../subtle/encrypt_then_authenticate';
import * as Random from '../subtle/random';
import * as Validators from '../subtle/validators';

import {Aead} from './internal/aead';

/**
 * @final
 */
class AesCtrHmacAeadKeyFactory implements KeyManager.KeyFactory {
  private static readonly VERSION: number = 0;
  private static readonly MIN_KEY_SIZE: number = 16;
  private static readonly MIN_IV_SIZE: number = 12;
  private static readonly MAX_IV_SIZE: number = 16;
  private static readonly MIN_TAG_SIZE: number = 10;
  private static readonly MAX_TAG_SIZE = new Map([
    [PbHashType.SHA1, 20], [PbHashType.SHA256, 32], [PbHashType.SHA512, 64]
  ]);

  /**
   */
  newKey(keyFormat: PbMessage|Uint8Array) {
    let keyFormatProto: PbAesCtrHmacAeadKeyFormat;
    if (keyFormat instanceof Uint8Array) {
      try {
        keyFormatProto = PbAesCtrHmacAeadKeyFormat.deserializeBinary(keyFormat);
      } catch (e) {
        throw new SecurityException(
            'Could not parse the given Uint8Array as a serialized proto of ' +
            AesCtrHmacAeadKeyManager.KEY_TYPE);
      }
      if (!keyFormatProto || !keyFormatProto.getAesCtrKeyFormat() ||
          !keyFormatProto.getHmacKeyFormat()) {
        throw new SecurityException(
            'Could not parse the given Uint8Array as a serialized proto of ' +
            AesCtrHmacAeadKeyManager.KEY_TYPE);
      }
    } else if (keyFormat instanceof PbAesCtrHmacAeadKeyFormat) {
      keyFormatProto = keyFormat;
    } else {
      throw new SecurityException('Expected AesCtrHmacAeadKeyFormat-proto');
    }

    const {aesCtrParams, aesCtrKeySize} =
        this.validateAesCtrKeyFormat(keyFormatProto.getAesCtrKeyFormat());
    const aesCtrKey = (new PbAesCtrKey())
                          .setVersion(AesCtrHmacAeadKeyFactory.VERSION)
                          .setParams(aesCtrParams)
                          .setKeyValue(Random.randBytes(aesCtrKeySize));
    const {hmacParams, hmacKeySize} =
        this.validateHmacKeyFormat(keyFormatProto.getHmacKeyFormat());
    const hmacKey = (new PbHmacKey())
                        .setVersion(AesCtrHmacAeadKeyFactory.VERSION)
                        .setParams(hmacParams)
                        .setKeyValue(Random.randBytes(hmacKeySize));
    const aesCtrHmacAeadKey =
        (new PbAesCtrHmacAeadKey()).setAesCtrKey(aesCtrKey).setHmacKey(hmacKey);
    return aesCtrHmacAeadKey;
  }

  /**
   */
  newKeyData(serializedKeyFormat: Uint8Array) {
    const key = (this.newKey(serializedKeyFormat));
    const keyData =
        (new PbKeyData())
            .setTypeUrl(AesCtrHmacAeadKeyManager.KEY_TYPE)
            .setValue(key.serializeBinary())
            .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
    return keyData;
  }

  // helper functions
  /**
   * Checks the parameters and size of a given keyFormat.
   *
   */
  validateAesCtrKeyFormat(keyFormat: null|PbAesCtrKeyFormat):
      {aesCtrParams: PbAesCtrParams, aesCtrKeySize: number, ivSize: number} {
    if (!keyFormat) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: key format undefined');
    }
    const aesCtrKeySize = keyFormat.getKeySize();
    Validators.validateAesKeySize(aesCtrKeySize);
    const aesCtrParams = keyFormat.getParams();
    if (!aesCtrParams) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: params undefined');
    }
    const ivSize = aesCtrParams.getIvSize();
    if (ivSize < AesCtrHmacAeadKeyFactory.MIN_IV_SIZE ||
        ivSize > AesCtrHmacAeadKeyFactory.MAX_IV_SIZE) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: IV size is out of range: ' +
          ivSize);
    }
    return {aesCtrParams, aesCtrKeySize, ivSize};
  }

  /**
   * Checks the parameters and size of a given keyFormat.
   *
   */
  validateHmacKeyFormat(keyFormat: null|PbHmacKeyFormat): {
    hmacParams: PbHmacParams,
    hmacKeySize: number,
    hashType: string,
    tagSize: number,
  } {
    if (!keyFormat) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: key format undefined');
    }
    const hmacKeySize = keyFormat.getKeySize();
    if (hmacKeySize < AesCtrHmacAeadKeyFactory.MIN_KEY_SIZE) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: HMAC key is too small: ' +
          keyFormat.getKeySize());
    }
    const hmacParams = keyFormat.getParams();
    if (!hmacParams) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: params undefined');
    }
    const tagSize = hmacParams.getTagSize();
    if (tagSize < AesCtrHmacAeadKeyFactory.MIN_TAG_SIZE) {
      throw new SecurityException(
          'Invalid HMAC params: tag size ' + tagSize + ' is too small.');
    }
    if (!AesCtrHmacAeadKeyFactory.MAX_TAG_SIZE.has(hmacParams.getHash())) {
      throw new SecurityException('Unknown hash type.');
    } else if (
        tagSize >
        AesCtrHmacAeadKeyFactory.MAX_TAG_SIZE.get(hmacParams.getHash())!) {
      throw new SecurityException(
          'Invalid HMAC params: tag size ' + tagSize + ' is out of range.');
    }
    let hashType: string;
    switch (hmacParams.getHash()) {
      case PbHashType.SHA1:
        hashType = 'SHA-1';
        break;
      case PbHashType.SHA256:
        hashType = 'SHA-256';
        break;
      case PbHashType.SHA512:
        hashType = 'SHA-512';
        break;
      default:
        hashType = 'UNKNOWN HASH';
    }
    return {hmacParams, hmacKeySize, hashType, tagSize};
  }
}

/**
 * @final
 */
export class AesCtrHmacAeadKeyManager implements KeyManager.KeyManager<Aead> {
  private static readonly SUPPORTED_PRIMITIVE = Aead;
  static KEY_TYPE: string =
      'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
  private static readonly VERSION: number = 0;
  private readonly keyFactory = new AesCtrHmacAeadKeyFactory();

  /**
   */
  async getPrimitive(
      primitiveType: Constructor<Aead>, key: PbKeyData|PbMessage) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    let deserializedKey: PbAesCtrHmacAeadKey;
    if (key instanceof PbKeyData) {
      if (!this.doesSupport(key.getTypeUrl())) {
        throw new SecurityException(
            'Key type ' + key.getTypeUrl() +
            ' is not supported. This key manager supports ' +
            this.getKeyType() + '.');
      }
      try {
        deserializedKey = PbAesCtrHmacAeadKey.deserializeBinary(key.getValue());
      } catch (e) {
        throw new SecurityException(
            'Could not parse the key in key data as a serialized proto of ' +
            AesCtrHmacAeadKeyManager.KEY_TYPE);
      }
      if (deserializedKey === null || deserializedKey === undefined) {
        throw new SecurityException(
            'Could not parse the key in key data as a serialized proto of ' +
            AesCtrHmacAeadKeyManager.KEY_TYPE);
      }
    } else if (key instanceof PbAesCtrHmacAeadKey) {
      deserializedKey = key;
    } else {
      throw new SecurityException(
          'Given key type is not supported. ' +
          'This key manager supports ' + this.getKeyType() + '.');
    }

    const {aesCtrKeyValue, ivSize} =
        this.validateAesCtrKey(deserializedKey.getAesCtrKey());
    const {hmacKeyValue, hashType, tagSize} =
        this.validateHmacKey(deserializedKey.getHmacKey());
    return await aesCtrHmacFromRawKeys(
        aesCtrKeyValue, ivSize, hashType, hmacKeyValue, tagSize);
  }

  /**
   */
  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  /**
   */
  getKeyType() {
    return AesCtrHmacAeadKeyManager.KEY_TYPE;
  }

  /**
   */
  getPrimitiveType() {
    return AesCtrHmacAeadKeyManager.SUPPORTED_PRIMITIVE;
  }

  /**
   */
  getVersion() {
    return AesCtrHmacAeadKeyManager.VERSION;
  }

  /**
   */
  getKeyFactory() {
    return this.keyFactory;
  }

  // helper functions
  /**
   * Checks the parameters and size of a given AES-CTR key.
   *
   */
  private validateAesCtrKey(key: null|PbAesCtrKey):
      {aesCtrKeyValue: Uint8Array, ivSize: number} {
    if (!key) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: key undefined');
    }
    Validators.validateVersion(key.getVersion(), this.getVersion());
    const keyFormat = (new PbAesCtrKeyFormat())
                          .setParams(key.getParams())
                          .setKeySize(key.getKeyValue_asU8().length);
    const {ivSize} = this.keyFactory.validateAesCtrKeyFormat(keyFormat);
    return {aesCtrKeyValue: key.getKeyValue_asU8(), ivSize};
  }

  /**
   * Checks the parameters and size of a given HMAC key.
   *
   */
  private validateHmacKey(key: null|PbHmacKey):
      {hmacKeyValue: Uint8Array, hashType: string, tagSize: number} {
    if (!key) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: key undefined');
    }
    Validators.validateVersion(key.getVersion(), this.getVersion());
    const keyFormat = (new PbHmacKeyFormat())
                          .setParams(key.getParams())
                          .setKeySize(key.getKeyValue_asU8().length);
    const {hashType, tagSize} =
        this.keyFactory.validateHmacKeyFormat(keyFormat);
    return {hmacKeyValue: key.getKeyValue_asU8(), hashType, tagSize};
  }

  static register() {
    Registry.registerKeyManager(new AesCtrHmacAeadKeyManager());
  }
}
