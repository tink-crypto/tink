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
  constructor() {
    /**
     * @const @private {string}
     */
    this.KEY_TYPE_ = 'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
    /**
     * @const @private {number}
     */
    this.VERSION_ = 0;

    /**
     * @const @private {number}
     */
    this.MIN_KEY_SIZE_ = 16;
    /**
     * @const @private {number}
     */
    this.MIN_IV_SIZE_ = 12;
    /**
     * @const @private {number}
     */
    this.MAX_IV_SIZE_ = 16;
    /**
     * @const @private {number}
     */
    this.MIN_TAG_SIZE_ = 10;
    /**
     * @const @private {Map<PbHashType, number>}
     */
    this.MAX_TAG_SIZE_ = new Map([
        [PbHashType.SHA1, 20],
        [PbHashType.SHA256, 32],
        [PbHashType.SHA512, 64]]);
  }

  /**
   * @override
   */
  async newKey(keyFormat) {
    var /** PbAesCtrHmacAeadKeyFormat */ keyFormatProto;
    if (keyFormat instanceof Uint8Array) {
      try {
        keyFormatProto = PbAesCtrHmacAeadKeyFormat.deserializeBinary(keyFormat);
      } catch (e) {
        throw new SecurityException(
            'Could not parse the given Uint8Array as a serialized proto of ' +
            this.KEY_TYPE_);
      }
      if (!keyFormatProto || !keyFormatProto.getAesCtrKeyFormat() ||
          !keyFormatProto.getHmacKeyFormat()) {
        throw new SecurityException(
            'Could not parse the given Uint8Array as a serialized proto of ' +
            this.KEY_TYPE_);
      }
    } else {
      if (keyFormat instanceof PbAesCtrHmacAeadKeyFormat) {
        keyFormatProto = keyFormat;
      } else {
        throw new SecurityException('Expected AesCtrHmacAeadKeyFormat-proto');
      }
    }

    this.validateAesCtrKeyFormat(keyFormatProto.getAesCtrKeyFormat());
    let /** PbAesCtrKey */ aesCtrKey = new PbAesCtrKey();
    aesCtrKey.setVersion(this.VERSION_);
    aesCtrKey.setParams(keyFormatProto.getAesCtrKeyFormat().getParams());
    aesCtrKey.setKeyValue(
        Random.randBytes(keyFormatProto.getAesCtrKeyFormat().getKeySize()));

    this.validateHmacKeyFormat(keyFormatProto.getHmacKeyFormat());
    let /** PbHmacKey */ hmacKey = new PbHmacKey();
    hmacKey.setVersion(this.VERSION_);
    hmacKey.setParams(keyFormatProto.getHmacKeyFormat().getParams());
    hmacKey.setKeyValue(
        Random.randBytes(keyFormatProto.getHmacKeyFormat().getKeySize()));


    let /** PbAesCtrHmacAeadKey */ aesCtrHmacAeadKey =
        new PbAesCtrHmacAeadKey();
    aesCtrHmacAeadKey.setAesCtrKey(aesCtrKey);
    aesCtrHmacAeadKey.setHmacKey(hmacKey);

    return aesCtrHmacAeadKey;
  }

  /**
   * @override
   */
  async newKeyData(serializedKeyFormat) {
    const /** PbAesCtrHmacAeadKeyFormat */ key =
        await this.newKey(serializedKeyFormat);
    let /** PbKeyData */ keyData = new PbKeyData();

    keyData.setTypeUrl(this.KEY_TYPE_);
    keyData.setValue(key.serializeBinary());
    keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

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
    if (ivSize < this.MIN_IV_SIZE_ || ivSize > this.MAX_IV_SIZE_) {
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
    if (keyFormat.getKeySize() < this.MIN_KEY_SIZE_) {
      throw new SecurityException(
          'Invalid AES CTR HMAC key format: HMAC key is too small: ' +
          keyFormat.getKeySize());
    }
    const hmacParams = keyFormat.getParams();
    if (hmacParams.getTagSize() < this.MIN_TAG_SIZE_) {
      throw new SecurityException(
          'Invalid HMAC params: tag size ' + hmacParams.getTagSize() +
          ' is too small.');
    }
    if (!this.MAX_TAG_SIZE_.has(hmacParams.getHash())) {
      throw new SecurityException('Unknown hash type.');
    } else {
      if (hmacParams.getTagSize() >
          this.MAX_TAG_SIZE_.get(hmacParams.getHash())) {
        throw new SecurityException(
            'Invalid HMAC params: tag size ' + hmacParams.getTagSize() +
            ' is out of range.');
      }
    }
  }
}

/**
 * @implements {KeyManager.KeyManager<Aead>}
 * @final
 */
class AesCtrHmacAeadKeyManager {
  constructor() {
    /**
     * @const @private {string}
     */
    this.KEY_TYPE_ = 'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
    /**
     * @const @private {number}
     */
    this.VERSION_ = 0;
    /**
     * @const @private {!AesCtrHmacAeadKeyFactory}
     */
    this.keyFactory_ = new AesCtrHmacAeadKeyFactory();
  }

  /**
   * @override
   */
  async getPrimitive(key) {
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
            this.KEY_TYPE_);
      }
      if (deserializedKey === null || deserializedKey === undefined) {
        throw new SecurityException(
            'Could not parse the key in key data as a serialized proto of ' +
            this.KEY_TYPE_);
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
    return this.KEY_TYPE_;
  }

  /**
   * @override
   */
  getVersion() {
    return this.VERSION_;
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

    let keyFormat = new PbAesCtrKeyFormat();
    keyFormat.setParams(key.getParams());
    keyFormat.setKeySize(key.getKeyValue_asU8().length);
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

    let keyFormat = new PbHmacKeyFormat();
    keyFormat.setParams(key.getParams());
    keyFormat.setKeySize(key.getKeyValue_asU8().length);
    this.keyFactory_.validateHmacKeyFormat(keyFormat);
  }
}

exports = AesCtrHmacAeadKeyManager;
