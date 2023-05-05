/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as keyManager from '../internal/key_manager';
import {PbHashType, PbHmacKey, PbHmacKeyFormat, PbHmacParams, PbKeyData, PbMessage} from '../internal/proto';
import {bytesAsU8, bytesLength} from '../internal/proto_shims';
import * as registry from '../internal/registry';
import {Constructor} from '../internal/util';
import * as hmac from '../subtle/hmac';
import * as random from '../subtle/random';
import * as validators from '../subtle/validators';

import {Mac} from './internal/mac';

const VERSION = 0;
const SUPPORTED_PRIMITIVE = Mac;
const MIN_KEY_SIZE = 16;
const MIN_TAG_SIZE = 10;
const MAX_TAG_SIZE = new Map([
  [PbHashType.SHA1, 20], [PbHashType.SHA256, 32], [PbHashType.SHA384, 48],
  [PbHashType.SHA512, 64]
]);

/**
 * A container for methods that generate new HMAC keys.
 * @final
 */
class HmacKeyFactory implements keyManager.KeyFactory {
  /**
   * Generates a new random HMAC key according to 'keyFormat'.
   *
   * @param keyFormat is either a KeyFormat
   *     proto or a serialized KeyFormat proto
   * @return the new generated HMAC key
   */
  newKey(keyFormat: PbMessage|Uint8Array) : PbHmacKey {
    const keyFormatProto = getKeyFormatProto(keyFormat);
    const {hmacParams, hmacKeySize} = this.validateKeyFormat(keyFormatProto);

    return new PbHmacKey()
        .setVersion(VERSION)
        .setParams(hmacParams)
        .setKeyValue(random.randBytes(hmacKeySize));
  }

  /**
   * Generates a new random HMAC key based on the `serializedKeyFormat` and
   * returns it as a KeyData proto.
   */
  newKeyData(serializedKeyFormat: Uint8Array): PbKeyData {
    const key: PbHmacKey = this.newKey(serializedKeyFormat);
    return new PbKeyData()
        .setTypeUrl(HmacKeyManager.KEY_TYPE)
        .setValue(key.serializeBinary())
        .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  }

  validateKeyFormat(keyFormat: PbHmacKeyFormat):
      {hmacParams: PbHmacParams, hmacKeySize: number} {
    validators.validateVersion(keyFormat.getVersion(), VERSION);
    if (!keyFormat.getKeySize()) {
      throw new SecurityException('Invalid HMAC key format: key size not set');
    }
    if (keyFormat.getKeySize() < MIN_KEY_SIZE) {
      throw new SecurityException(
          `Key too short, must be at least ${MIN_KEY_SIZE} bytes.`);
    }
    const params: PbHmacParams|undefined = keyFormat.getParams();
    if (!params) {
      throw new SecurityException('Invalid HMAC key format: params not set');
    }
    const tagSize = params.getTagSize();
    if (!tagSize) {
      throw new SecurityException('Invalid HMAC params: tag size not set');
    }
    if (tagSize < MIN_TAG_SIZE) {
      throw new SecurityException(
          'Invalid HMAC params: tag size ' + String(tagSize) +
          ' is too small.');
    }
    const hashType = params.getHash();
    if (!MAX_TAG_SIZE.has(hashType)) {
      throw new SecurityException('Invalid HMAC params: unknown hash type');
    }
    if (tagSize > MAX_TAG_SIZE.get(hashType)!) {
      throw new SecurityException(
          'Invalid HMAC params: tag size ' + String(tagSize) +
          ' is too large.');
    }

    return {
      hmacParams: params,
      hmacKeySize: keyFormat.getKeySize(),
    };
  }
}

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an HmacKeyFormat-proto (otherwise).
   *
   */
function getKeyFormatProto(keyFormat: PbMessage|Uint8Array): PbHmacKeyFormat {
  if (keyFormat instanceof Uint8Array) {
    return deserializeKeyFormat(keyFormat);
    // Used because of the internal vs. external protobuf API discrepancies.
    // tslint:disable-next-line:jspb-casts
  } else if (keyFormat instanceof PbHmacKeyFormat) {
    return keyFormat;
  } else {
    throw new SecurityException('Expected HmacKeyFormat-proto');
  }
}

function deserializeKeyFormat(keyFormat: Uint8Array): PbHmacKeyFormat {
  let keyFormatProto: PbHmacKeyFormat;
  try {
    keyFormatProto = PbHmacKeyFormat.deserializeBinary(keyFormat);
  } catch (e) {
    throw new SecurityException(
        'Could not parse the input as a serialized proto of ' +
        HmacKeyManager.KEY_TYPE + ' key format.');
  }
  if (!keyFormatProto.getKeySize() || !keyFormatProto.getParams()) {
    throw new SecurityException(
        'Could not parse the input as a serialized proto of ' +
        HmacKeyManager.KEY_TYPE + ' key format.');
  }
  return keyFormatProto;
}


/**
 * Key manager that generates new {@link HmacKey} keys and produces new
 * instances of {@link Mac} primitives.
 *
 * @final
 */
export class HmacKeyManager implements keyManager.KeyManager<Mac> {
  static KEY_TYPE = 'type.googleapis.com/google.crypto.tink.HmacKey';
  private readonly keyFactory = new HmacKeyFactory();

  async getPrimitive(primitiveType: Constructor<Mac>, key: PbKeyData|PbMessage):
      Promise<Mac> {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not supported by this key manager.');
    }
    const keyProto = getKeyProto(key);
    const {hashType, keyValue, tagSize} = this.validateKey(keyProto);
    return await hmac.fromRawKey(hashType, keyValue, tagSize);
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return HmacKeyManager.KEY_TYPE;
  }

  getPrimitiveType() {
    return SUPPORTED_PRIMITIVE;
  }

  getVersion() {
    return VERSION;
  }

  getKeyFactory() {
    return this.keyFactory;
  }

  validateKey(key: PbHmacKey):
      {hashType: string, keyValue: Uint8Array, tagSize: number} {
    validators.validateVersion(key.getVersion(), VERSION);
    const keyFormat = (new PbHmacKeyFormat())
                          .setParams(key.getParams())
                          .setKeySize(bytesLength(key.getKeyValue()));
    const {hmacParams} = this.keyFactory.validateKeyFormat(keyFormat);
    let hashType: string;
    switch (hmacParams.getHash()) {
      case PbHashType.SHA1:
        hashType = 'SHA-1';
        break;
      case PbHashType.SHA256:
        hashType = 'SHA-256';
        break;
      case PbHashType.SHA384:
        hashType = 'SHA-384';
        break;
      case PbHashType.SHA512:
        hashType = 'SHA-512';
        break;
      default:
        throw new SecurityException('Unknown hash type');
    }
    return {
      hashType,
      keyValue: bytesAsU8(key.getKeyValue()),
      tagSize: hmacParams.getTagSize()
    };
  }

  static register() {
    registry.registerKeyManager(new HmacKeyManager());
  }
}

  /**
   * The input key is either deserialized (in case that the input is
   * KeyData-proto) or checked to be an HmacKey-proto (otherwise).
   *
   */
function getKeyProto(keyMaterial: PbMessage|PbKeyData): PbHmacKey {
  // tslint:disable:jspb-casts
  if (keyMaterial instanceof PbKeyData) {
    return getKeyProtoFromKeyData(keyMaterial);
  } else if (keyMaterial instanceof PbHmacKey) {
    return keyMaterial;
  } else {
    throw new SecurityException(
        'Key type is not supported. This key manager supports ' +
        HmacKeyManager.KEY_TYPE + '.');
  }  // tslint:enable:jspb-casts
}

  /**
   * It validates the key type and returns a deserialized HmacKey-proto.
   *
   */
function getKeyProtoFromKeyData(keyData: PbKeyData): PbHmacKey {
  if (keyData.getTypeUrl() !== HmacKeyManager.KEY_TYPE) {
    throw new SecurityException(
        'Key type ' + keyData.getTypeUrl() +
        ' is not supported. This key manager supports ' +
        HmacKeyManager.KEY_TYPE + '.');
  }
  let deserializedKey: PbHmacKey;
  try {
    deserializedKey = PbHmacKey.deserializeBinary(keyData.getValue());
  } catch (e) {
    throw new SecurityException(
        'Could not parse the input as a ' +
        'serialized proto of ' + HmacKeyManager.KEY_TYPE + ' key.');
  }
  return deserializedKey;
}
