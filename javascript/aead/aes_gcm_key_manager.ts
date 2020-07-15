// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import {SecurityException} from '../exception/security_exception';
import * as KeyManager from '../internal/key_manager';
import {PbAesGcmKey, PbAesGcmKeyFormat, PbKeyData, PbMessage} from '../internal/proto';
import * as Registry from '../internal/registry';
import * as aesGcm from '../subtle/aes_gcm';
import * as Random from '../subtle/random';
import * as Validators from '../subtle/validators';

import {Aead} from './internal/aead';

const VERSION = 0;

/**
 * @final
 */
class AesGcmKeyFactory implements KeyManager.KeyFactory {
  /** @override */
  newKey(keyFormat: AnyDuringMigration) {
    const keyFormatProto = AesGcmKeyFactory.getKeyFormatProto_(keyFormat);
    AesGcmKeyFactory.validateKeyFormat_(keyFormatProto);
    const key = (new PbAesGcmKey())
                    .setKeyValue(Random.randBytes(keyFormatProto.getKeySize()))
                    .setVersion(VERSION);
    return key;
  }

  /** @override */
  newKeyData(serializedKeyFormat: AnyDuringMigration) {
    const key = (this.newKey(serializedKeyFormat));
    const keyData =
        (new PbKeyData())
            .setTypeUrl(AesGcmKeyManager.KEY_TYPE)
            .setValue(key.serializeBinary())
            .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
    return keyData;
  }

  private static validateKeyFormat_(keyFormat: PbAesGcmKeyFormat) {
    Validators.validateAesKeySize(keyFormat.getKeySize());
  }

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an AesGcmKeyFormat-proto (otherwise).
   *
   */
  private static getKeyFormatProto_(keyFormat: PbMessage|
                                    Uint8Array): PbAesGcmKeyFormat {
    if (keyFormat instanceof Uint8Array) {
      return AesGcmKeyFactory.deserializeKeyFormat_(keyFormat);
    } else if (keyFormat instanceof PbAesGcmKeyFormat) {
      return keyFormat;
    } else {
      throw new SecurityException('Expected AesGcmKeyFormat-proto');
    }
  }

  private static deserializeKeyFormat_(keyFormat: Uint8Array):
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
  private static readonly SUPPORTED_PRIMITIVE_: AnyDuringMigration = Aead;
  static KEY_TYPE: string = 'type.googleapis.com/google.crypto.tink.AesGcmKey';
  private readonly keyFactory_: AesGcmKeyFactory;

  /** Visible for testing. */
  constructor() {
    this.keyFactory_ = new AesGcmKeyFactory();
  }

  /** @override */
  async getPrimitive(
      primitiveType: AnyDuringMigration, key: AnyDuringMigration) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    const keyProto = AesGcmKeyManager.getKeyProto_(key);
    AesGcmKeyManager.validateKey_(keyProto);
    return await aesGcm.fromRawKey(keyProto.getKeyValue_asU8());
  }

  /** @override */
  doesSupport(keyType: AnyDuringMigration) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return AesGcmKeyManager.KEY_TYPE;
  }

  /** @override */
  getPrimitiveType() {
    return AesGcmKeyManager.SUPPORTED_PRIMITIVE_;
  }

  /** @override */
  getVersion() {
    return VERSION;
  }

  /** @override */
  getKeyFactory() {
    return this.keyFactory_;
  }

  private static validateKey_(key: PbAesGcmKey) {
    Validators.validateAesKeySize(key.getKeyValue().length);
    Validators.validateVersion(key.getVersion(), VERSION);
  }

  /**
   * The input key is either deserialized (in case that the input is
   * KeyData-proto) or checked to be an AesGcmKey-proto (otherwise).
   *
   */
  private static getKeyProto_(keyMaterial: PbMessage|PbKeyData): PbAesGcmKey {
    if (keyMaterial instanceof PbKeyData) {
      return AesGcmKeyManager.getKeyProtoFromKeyData_(keyMaterial);
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
  private static getKeyProtoFromKeyData_(keyData: PbKeyData): PbAesGcmKey {
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
