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
const KeyManager = goog.require('tink.KeyManager');
const Map = goog.require('goog.structs.Map');
const PbAesCtrHmacAeadKey = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKey');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKey = goog.require('proto.google.crypto.tink.AesCtrKey');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKey = goog.require('proto.google.crypto.tink.HmacKey');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbMessage = goog.require('jspb.Message');
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
    this.MAX_TAG_SIZE_ = new Map(
        PbHashType.SHA1, 20,
        PbHashType.SHA256, 32,
        PbHashType.SHA512, 64);
  }

  /**
   * @override
   */
  async newKey(keyFormat) {
    var /** PbAesCtrHmacAeadKeyFormat */ keyFormatProto;
    if (!(keyFormat instanceof PbMessage)) {
      try {
        keyFormatProto = new PbAesCtrHmacAeadKeyFormat(
            /** @type{Array}*/ (JSON.parse(keyFormat)));
      } catch (e) {
        throw new SecurityException(
            'Could not parse the given string as a serialized proto of ' +
            this.KEY_TYPE_);
      }
    } else {
      if (keyFormat instanceof PbAesCtrHmacAeadKeyFormat) {
        keyFormatProto = keyFormat;
      } else {
        throw new SecurityException('Expected AesCtrHmacAeadKeyFormat-proto');
      }
    }
    this.validateAesCtrKeyFormat_((keyFormatProto.getAesCtrKeyFormat()));
    let /** PbAesCtrKey */ aesCtrKey = new PbAesCtrKey();
    aesCtrKey.setVersion(this.VERSION_);
    aesCtrKey.setParams(keyFormatProto.getAesCtrKeyFormat().getParams());
    aesCtrKey.setKeyValue(
        Random.randBytes(keyFormatProto.getAesCtrKeyFormat().getKeySize()));

    this.validateHmacKeyFormat_(keyFormatProto.getHmacKeyFormat());
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
  // TODO
  async newKeyData(serializedKeyFormat) {
    throw new SecurityException('Not implemented yet');
  }

  // helper functions
  /**
   * Checks the parameters and size of a given keyFormat.
   *
   * @param {null|!PbAesCtrKeyFormat} keyFormat
   * @private
   */
  validateAesCtrKeyFormat_(keyFormat) {
    if (keyFormat == null) {
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
   * @private
   */
  validateHmacKeyFormat_(keyFormat) {
    if (keyFormat == null) {
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
    if (!this.MAX_TAG_SIZE_.containsKey(hmacParams.getHash())) {
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
     * @const @private {AesCtrHmacAeadKeyFactory}
     */
    this.keyFactory_ = new AesCtrHmacAeadKeyFactory();
  }

  /**
   * @override
   */
  // TODO
  async getPrimitive(key) {
    throw new SecurityException('Not implemented yet');
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
}

exports = {
  AesCtrHmacAeadKeyManager
};
