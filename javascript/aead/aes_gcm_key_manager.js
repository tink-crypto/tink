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

goog.module('tink.aead.AesGcmKeyManager');

const Aead = goog.require('tink.Aead');
const AesGcm = goog.require('tink.subtle.AesGcm');
const KeyManager = goog.require('tink.KeyManager');
const PbAesGcmKey = goog.require('proto.google.crypto.tink.AesGcmKey');
const PbAesGcmKeyFormat = goog.require('proto.google.crypto.tink.AesGcmKeyFormat');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbMessage = goog.require('jspb.Message');
const Random = goog.require('tink.subtle.Random');
const SecurityException = goog.require('tink.exception.SecurityException');
const Validators = goog.require('tink.subtle.Validators');

/**
 * @final
 * @implements {KeyManager.KeyFactory}
 */
class AesGcmKeyFactory {
  /** @override */
  newKey(keyFormat) {
    const keyFormatProto = AesGcmKeyFactory.getKeyFormatProto_(keyFormat);

    AesGcmKeyFactory.validateKeyFormat_(keyFormatProto);

    const key = new PbAesGcmKey()
                    .setKeyValue(Random.randBytes(keyFormatProto.getKeySize()))
                    .setVersion(AesGcmKeyManager.VERSION_);

    return key;
  }

  /** @override */
  newKeyData(serializedKeyFormat) {
    const key = /** @type {!PbAesGcmKey} */ (this.newKey(serializedKeyFormat));
    const keyData =
        new PbKeyData()
            .setTypeUrl(AesGcmKeyManager.KEY_TYPE)
            .setValue(key.serializeBinary())
            .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

    return keyData;
  }

  /**
   * @private
   * @param {!PbAesGcmKeyFormat} keyFormat
   */
  static validateKeyFormat_(keyFormat) {
    Validators.validateAesKeySize(keyFormat.getKeySize());
  }

  /**
   * The input keyFormat is either deserialized (in case that the input is
   * Uint8Array) or checked to be an AesGcmKeyFormat-proto (otherwise).
   *
   * @private
   * @param {!PbMessage|!Uint8Array} keyFormat
   * @return {!PbAesGcmKeyFormat}
   */
  static getKeyFormatProto_(keyFormat) {
    if (keyFormat instanceof Uint8Array) {
      return AesGcmKeyFactory.deserializeKeyFormat_(keyFormat);
    } else {
      if (keyFormat instanceof PbAesGcmKeyFormat) {
        return keyFormat;
      } else {
        throw new SecurityException('Expected AesGcmKeyFormat-proto');
      }
    }
  }

  /**
   * @private
   * @param {!Uint8Array} keyFormat
   * @return {!PbAesGcmKeyFormat}
   */
  static deserializeKeyFormat_(keyFormat) {
    let /** !PbAesGcmKeyFormat */ keyFormatProto;
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
 * @implements {KeyManager.KeyManager<Aead>}
 * @final
 */
class AesGcmKeyManager {
  constructor() {
    /** @const @private {!AesGcmKeyFactory} */
    this.keyFactory_ = new AesGcmKeyFactory();
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }

    const keyProto = AesGcmKeyManager.getKeyProto_(key);
    AesGcmKeyManager.validateKey_(keyProto);

    return await AesGcm.newInstance(keyProto.getKeyValue_asU8());
  }

  /** @override */
  doesSupport(keyType) {
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
    return AesGcmKeyManager.VERSION_;
  }

  /** @override */
  getKeyFactory() {
    return this.keyFactory_;
  }

  /**
   * @private
   * @param {!PbAesGcmKey} key
   */
  static validateKey_(key) {
    Validators.validateAesKeySize(key.getKeyValue().length);
    Validators.validateVersion(key.getVersion(), AesGcmKeyManager.VERSION_);
  }

  /**
   * The input key is either deserialized (in case that the input is
   * KeyData-proto) or checked to be an AesGcmKey-proto (otherwise).
   *
   * @private
   * @param {!PbMessage|!PbKeyData} keyMaterial
   * @return {!PbAesGcmKey}
   */
  static getKeyProto_(keyMaterial) {
    if (keyMaterial instanceof PbKeyData) {
      return AesGcmKeyManager.getKeyProtoFromKeyData_(keyMaterial);
    } else {
      if (keyMaterial instanceof PbAesGcmKey) {
        return keyMaterial;
      } else {
        throw new SecurityException(
            'Key type is not supported. ' +
            'This key manager supports ' + AesGcmKeyManager.KEY_TYPE + '.');
      }
    }
  }

  /**
   * It validates the key type and returns a deserialized AesGcmKey-proto.
   *
   * @private
   * @param {!PbKeyData} keyData
   * @return {!PbAesGcmKey}
   */
  static getKeyProtoFromKeyData_(keyData) {
    if (keyData.getTypeUrl() != AesGcmKeyManager.KEY_TYPE) {
      throw new SecurityException(
          'Key type ' + keyData.getTypeUrl() +
          ' is not supported. This key manager supports ' +
          AesGcmKeyManager.KEY_TYPE + '.');
    }

    let /** PbAesGcmKey */ deserializedKey;
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
}

/** @const @private {!Object} */
AesGcmKeyManager.SUPPORTED_PRIMITIVE_ = Aead;

/** @const @public {string} */
AesGcmKeyManager.KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesGcmKey';

/** @const @private {number} */
AesGcmKeyManager.VERSION_ = 0;

exports = AesGcmKeyManager;
