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

goog.module('tink.aead.AesCtrHmacAeadKeyManager');

const Aead = goog.require('tink.Aead');
const EncryptThenAuthenticate = goog.require('tink.subtle.EncryptThenAuthenticate');
const KeyManager = goog.require('tink.KeyManager');
const PbAesCtrHmacAeadKey = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKey');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKey = goog.require('proto.google.crypto.tink.AesCtrKey');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKey = goog.require('proto.google.crypto.tink.HmacKey');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const Random = goog.require('tink.subtle.Random');
const SecurityException = goog.require('tink.exception.SecurityException');
const Validators = goog.require('tink.subtle.Validators');

/**
 * @final
 * @implements {KeyManager.KeyFactory}
 */
class AesCtrHmacAeadKeyFactory {
  /**
   * @override
   */
  newKey(keyFormat) {
    let /** PbAesCtrHmacAeadKeyFormat */ keyFormatProto;
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
    } else {
      if (keyFormat instanceof PbAesCtrHmacAeadKeyFormat) {
        keyFormatProto = keyFormat;
      } else {
        throw new SecurityException('Expected AesCtrHmacAeadKeyFormat-proto');
      }
    }

    this.validateAesCtrKeyFormat(keyFormatProto.getAesCtrKeyFormat());
    let aesCtrKey =
        new PbAesCtrKey()
            .setVersion(AesCtrHmacAeadKeyFactory.VERSION_)
            .setParams(keyFormatProto.getAesCtrKeyFormat().getParams())
            .setKeyValue(Random.randBytes(
                keyFormatProto.getAesCtrKeyFormat().getKeySize()));

    this.validateHmacKeyFormat(keyFormatProto.getHmacKeyFormat());
    let hmacKey = new PbHmacKey()
                      .setVersion(AesCtrHmacAeadKeyFactory.VERSION_)
                      .setParams(keyFormatProto.getHmacKeyFormat().getParams())
                      .setKeyValue(Random.randBytes(
                          keyFormatProto.getHmacKeyFormat().getKeySize()));


    let aesCtrHmacAeadKey =
        new PbAesCtrHmacAeadKey().setAesCtrKey(aesCtrKey).setHmacKey(hmacKey);

    return aesCtrHmacAeadKey;
  }

  /**
   * @override
   */
  newKeyData(serializedKeyFormat) {
    const key =
        /** @type {!PbAesCtrHmacAeadKey} */ (this.newKey(serializedKeyFormat));
    let keyData = new PbKeyData()
                      .setTypeUrl(AesCtrHmacAeadKeyManager.KEY_TYPE)
                      .setValue(key.serializeBinary())
                      .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

    return keyData;
  }

  // helper functions
  /**
   * Checks the parameters and size of a given keyFormat.
   *
   * @param {null|!PbAesCtrKeyFormat} keyFormat
   */
  validateAesCtrKeyFormat(keyFormat) {
    if (!keyFormat) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: key format undefined');
    }
    Validators.validateAesKeySize(keyFormat.getKeySize());
    const ivSize = keyFormat.getParams().getIvSize();
    if (ivSize < AesCtrHmacAeadKeyFactory.MIN_IV_SIZE_ ||
        ivSize > AesCtrHmacAeadKeyFactory.MAX_IV_SIZE_) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: IV size is out of range: ' +
          ivSize);
    }
  }

  /**
   * Checks the parameters and size of a given keyFormat.
   *
   * @param {null|!PbHmacKeyFormat} keyFormat
   */
  validateHmacKeyFormat(keyFormat) {
    if (!keyFormat) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: key format undefined');
    }
    if (keyFormat.getKeySize() < AesCtrHmacAeadKeyFactory.MIN_KEY_SIZE_) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: HMAC key is too small: ' +
          keyFormat.getKeySize());
    }
    const hmacParams = keyFormat.getParams();
    if (hmacParams.getTagSize() < AesCtrHmacAeadKeyFactory.MIN_TAG_SIZE_) {
      throw new SecurityException(
          'Invalid HMAC params: tag size ' + hmacParams.getTagSize() +
          ' is too small.');
    }
    if (!AesCtrHmacAeadKeyFactory.MAX_TAG_SIZE_.has(hmacParams.getHash())) {
      throw new SecurityException('Unknown hash type.');
    } else {
      if (hmacParams.getTagSize() >
          AesCtrHmacAeadKeyFactory.MAX_TAG_SIZE_.get(hmacParams.getHash())) {
        throw new SecurityException(
            'Invalid HMAC params: tag size ' + hmacParams.getTagSize() +
            ' is out of range.');
      }
    }
  }
}
/**
 * @const @private {number}
 */
AesCtrHmacAeadKeyFactory.VERSION_ = 0;

/**
 * @const @private {number}
 */
AesCtrHmacAeadKeyFactory.MIN_KEY_SIZE_ = 16;
/**
 * @const @private {number}
 */
AesCtrHmacAeadKeyFactory.MIN_IV_SIZE_ = 12;
/**
 * @const @private {number}
 */
AesCtrHmacAeadKeyFactory.MAX_IV_SIZE_ = 16;
/**
 * @const @private {number}
 */
AesCtrHmacAeadKeyFactory.MIN_TAG_SIZE_ = 10;
/**
 * @const @private {!Map<!PbHashType, number>}
 */
AesCtrHmacAeadKeyFactory.MAX_TAG_SIZE_ = new Map(
    [[PbHashType.SHA1, 20], [PbHashType.SHA256, 32], [PbHashType.SHA512, 64]]);

/**
 * @implements {KeyManager.KeyManager<Aead>}
 * @final
 */
class AesCtrHmacAeadKeyManager {
  constructor() {
    /**
     * @const @private {!AesCtrHmacAeadKeyFactory}
     */
    this.keyFactory_ = new AesCtrHmacAeadKeyFactory();
  }

  /**
   * @override
   */
  async getPrimitive(primitiveType, key) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }

    let /** PbAesCtrHmacAeadKey */ deserializedKey;
    if (key instanceof PbKeyData) {
      if (!this.doesSupport(key.getTypeUrl())) {
        throw new SecurityException('Key type ' + key.getTypeUrl() +
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
    } else {
      if (key instanceof PbAesCtrHmacAeadKey) {
        deserializedKey = key;
      } else {
        throw new SecurityException('Given key type is not supported. ' +
          'This key manager supports ' + this.getKeyType() + '.');
      }
    }

    const aesCtrKey = deserializedKey.getAesCtrKey();
    this.validateAesCtrKey_(aesCtrKey);
    const hmacKey = deserializedKey.getHmacKey();
    this.validateHmacKey_(hmacKey);

    let /** string */ hashType;
    switch (hmacKey.getParams().getHash()) {
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

    const aead = await EncryptThenAuthenticate.newAesCtrHmac(
        aesCtrKey.getKeyValue_asU8(), aesCtrKey.getParams().getIvSize(),
        hashType, hmacKey.getKeyValue_asU8(), hmacKey.getParams().getTagSize());

    return aead;
  }

  /**
   * @override
   */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }

  /**
   * @override
   */
  getKeyType() {
    return AesCtrHmacAeadKeyManager.KEY_TYPE;
  }

  /**
   * @override
   */
  getPrimitiveType() {
    return AesCtrHmacAeadKeyManager.SUPPORTED_PRIMITIVE_;
  }

  /**
   * @override
   */
  getVersion() {
    return AesCtrHmacAeadKeyManager.VERSION_;
  }

  /**
   * @override
   */
  getKeyFactory() {
    return this.keyFactory_;
  }

  // helper functions
  /**
   * Checks the parameters and size of a given AES-CTR key.
   *
   * @param {null|!PbAesCtrKey} key
   * @private
   */
  validateAesCtrKey_(key) {
    if (!key) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: key undefined');
    }

    Validators.validateVersion(key.getVersion(), this.getVersion());

    let keyFormat = new PbAesCtrKeyFormat()
                        .setParams(key.getParams())
                        .setKeySize(key.getKeyValue_asU8().length);
    this.keyFactory_.validateAesCtrKeyFormat(keyFormat);
  }


  /**
   * Checks the parameters and size of a given HMAC key.
   *
   * @param {null|!PbHmacKey} key
   * @private
   */
  validateHmacKey_(key) {
    if (!key) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: key undefined');
    }

    Validators.validateVersion(key.getVersion(), this.getVersion());

    let keyFormat = new PbHmacKeyFormat()
                        .setParams(key.getParams())
                        .setKeySize(key.getKeyValue_asU8().length);
    this.keyFactory_.validateHmacKeyFormat(keyFormat);
  }
}

/**
 * @const @private {!Object}
 */
AesCtrHmacAeadKeyManager.SUPPORTED_PRIMITIVE_ = Aead;

/**
 * @const @public {string}
 */
AesCtrHmacAeadKeyManager.KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
/**
 * @const @private {number}
 */
AesCtrHmacAeadKeyManager.VERSION_ = 0;

exports = AesCtrHmacAeadKeyManager;
