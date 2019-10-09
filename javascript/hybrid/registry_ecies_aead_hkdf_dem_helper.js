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

goog.module('tink.hybrid.RegistryEciesAeadHkdfDemHelper');

const Aead = goog.require('tink.Aead');
const AeadConfig = goog.require('tink.aead.AeadConfig');
const EciesAeadHkdfDemHelper = goog.require('tink.subtle.EciesAeadHkdfDemHelper');
const PbAesCtrHmacAeadKey = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKey');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesGcmKey = goog.require('proto.google.crypto.tink.AesGcmKey');
const PbAesGcmKeyFormat = goog.require('proto.google.crypto.tink.AesGcmKeyFormat');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const Registry = goog.require('tink.Registry');
const SecurityException = goog.require('tink.exception.SecurityException');


/**
 * @implements {EciesAeadHkdfDemHelper}
 * @final
 */
class RegistryEciesAeadHkdfDemHelper {
  /**
   * @param {!PbKeyTemplate} keyTemplate
   */
  constructor(keyTemplate) {
    let /** @type {number} */ demKeySize;
    let /** @type {number} */ aesCtrKeySize;
    let /** @type {!PbAesCtrHmacAeadKeyFormat|!PbAesGcmKeyFormat} */ keyFormat;
    const keyTypeUrl = keyTemplate.getTypeUrl();

    switch (keyTypeUrl) {
      case AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL:
        keyFormat =
            RegistryEciesAeadHkdfDemHelper.getAesCtrHmacKeyFormat_(keyTemplate);
        aesCtrKeySize = keyFormat.getAesCtrKeyFormat().getKeySize();
        const hmacKeySize = keyFormat.getHmacKeyFormat().getKeySize();
        demKeySize = aesCtrKeySize + hmacKeySize;
        break;

      case AeadConfig.AES_GCM_TYPE_URL:
        keyFormat =
            RegistryEciesAeadHkdfDemHelper.getAesGcmKeyFormat_(keyTemplate);
        demKeySize = keyFormat.getKeySize();
        break;

      default:
        throw new SecurityException(
            'Key type URL ' + keyTypeUrl + ' is not supported.');
    }

    const keyFactory = Registry.getKeyManager(keyTypeUrl).getKeyFactory();
    /** @const @private {!PbAesCtrHmacAeadKey|!PbAesGcmKey} */
    this.key_ = /** @type {!PbAesCtrHmacAeadKey|!PbAesGcmKey} */ (
        keyFactory.newKey(keyFormat));
    /** @const @private {string} */
    this.demKeyTypeUrl_ = keyTypeUrl;
    /** @const @private {number} */
    this.demKeySize_ = demKeySize;
    /** @const @private {number} */
    this.aesCtrKeySize_ = aesCtrKeySize;
  }

  /**
   * @override
   */
  getDemKeySizeInBytes() {
    return this.demKeySize_;
  }

  /**
   * @override
   */
  async getAead(symmetricKey) {
    if (symmetricKey.length != this.demKeySize_) {
      throw new SecurityException(
          'Key is not of the correct length, expected length: ' +
          this.demKeySize_ + ', but got key of length: ' + symmetricKey.length +
          '.');
    }

    let /** @type {!PbAesCtrHmacAeadKey|!PbAesGcmKey} */ key;
    if (this.demKeyTypeUrl_ === AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL) {
      key = this.replaceAesCtrHmacKeyValue_(symmetricKey);
    } else {
      key = this.replaceAesGcmKeyValue_(symmetricKey);
    }

    return await Registry.getPrimitive(Aead, key, this.demKeyTypeUrl_);
  }

  /**
   * @private
   *
   * @param {!PbKeyTemplate} keyTemplate
   *
   * @return {!PbAesGcmKeyFormat}
   */
  static getAesGcmKeyFormat_(keyTemplate) {
    let /** @type{!PbAesGcmKeyFormat} */ keyFormat;
    try {
      keyFormat = PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue());
    } catch (e) {
      throw new SecurityException(
          'Could not parse the given Uint8Array as a serialized proto of ' +
          AeadConfig.AES_GCM_TYPE_URL + '.');
    }
    if (!keyFormat.getKeySize()) {
      throw new SecurityException(
          'Could not parse the given Uint8Array as a serialized proto of ' +
          AeadConfig.AES_GCM_TYPE_URL + '.');
    }
    return keyFormat;
  }

  /**
   * @private
   *
   * @param {!PbKeyTemplate} keyTemplate
   *
   * @return {!PbAesCtrHmacAeadKeyFormat}
   */
  static getAesCtrHmacKeyFormat_(keyTemplate) {
    let /** @type{!PbAesCtrHmacAeadKeyFormat} */ keyFormat;
    try {
      keyFormat =
          PbAesCtrHmacAeadKeyFormat.deserializeBinary(keyTemplate.getValue());
    } catch (e) {
      throw new SecurityException(
          'Could not parse the given Uint8Array ' +
          'as a serialized proto of ' + AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL +
          '.');
    }
    if (!keyFormat.getAesCtrKeyFormat() || !keyFormat.getHmacKeyFormat()) {
      throw new SecurityException(
          'Could not parse the given Uint8Array as a serialized proto of ' +
          AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL + '.');
    }
    return keyFormat;
  }


  /**
   * @private
   *
   * @param {!Uint8Array} symmetricKey
   *
   * @return {!PbAesGcmKey}
   */
  replaceAesGcmKeyValue_(symmetricKey) {
    const key = this.key_.setKeyValue(symmetricKey);
    return key;
  }

  /**
   * @private
   *
   * @param {!Uint8Array} symmetricKey
   *
   * @return {!PbAesCtrHmacAeadKey}
   */
  replaceAesCtrHmacKeyValue_(symmetricKey) {
    const key = /** @type {!PbAesCtrHmacAeadKey} */ (this.key_);

    const aesCtrKeyValue = symmetricKey.slice(0, this.aesCtrKeySize_);
    key.getAesCtrKey().setKeyValue(aesCtrKeyValue);

    const hmacKeyValue =
        symmetricKey.slice(this.aesCtrKeySize_, this.demKeySize_);
    key.getHmacKey().setKeyValue(hmacKeyValue);

    return key;
  }
}

exports = RegistryEciesAeadHkdfDemHelper;
