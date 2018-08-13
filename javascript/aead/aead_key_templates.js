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

goog.module('tink.aead.AeadKeyTemplates');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbAesCtrParams = goog.require('proto.google.crypto.tink.AesCtrParams');
const PbAesGcmKeyFormat = goog.require('proto.google.crypto.tink.AesGcmKeyFormat');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbHmacParams = goog.require('proto.google.crypto.tink.HmacParams');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');

/**
 * Pre-generated KeyTemplates for Aead keys.
 *
 * One can use these templates to generate new Keyset with
 * KeysetHandle.generateNew method. To generate a new keyset that contains a
 * single AesCtrHmacAeadKey, one can do:
 *
 * AeadConfig.Register();
 * KeysetHandle handle =
 *     KeysetHandle.generateNew(AeadKeyTemplates.aes128CtrHmacSha256());
 *
 * @final
 */
class AeadKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of AesCtrHmacAeadKey
   * with the following parameters:
   *    AES key size: 16 bytes
   *    AES IV size: 16 bytes
   *    HMAC key size: 32 bytes
   *    HMAC tag size: 16 bytes
   *    HMAC hash function: SHA256
   *    OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static aes128CtrHmacSha256() {
    return AeadKeyTemplates.newAesCtrHmacSha256KeyTemplate_(
        /* aesKeySize = */ 16,
        /* ivSize = */ 16,
        /* hmacKeySize = */ 32,
        /* tagSize = */ 16);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesCtrHmacAeadKey
   * with the following parameters:
   *    AES key size: 32 bytes
   *    AES IV size: 16 bytes
   *    HMAC key size: 32 bytes
   *    HMAC tag size: 32 bytes
   *    HMAC hash function: SHA256
   *    OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static aes256CtrHmacSha256() {
    return AeadKeyTemplates.newAesCtrHmacSha256KeyTemplate_(
        /* aesKeySize = */ 32,
        /* ivSize = */ 16,
        /* hmacKeySize = */ 32,
        /* tagSize = */ 32);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 16 bytes
   *
   * @return {!PbKeyTemplate}
   */
  static aes128Gcm() {
    return AeadKeyTemplates.newAesGcmKeyTemplate_(/* keySize = */ 16);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 32 bytes
   *
   * @return {!PbKeyTemplate}
   */
  static aes256Gcm() {
    return AeadKeyTemplates.newAesGcmKeyTemplate_(/* keySize = */ 32);
  }

  /**
   * @private
   *
   * @param {number} aesKeySize
   * @param {number} ivSize
   * @param {number} hmacKeySize
   * @param {number} tagSize
   *
   * @return {!PbKeyTemplate}
   */
  static newAesCtrHmacSha256KeyTemplate_(
      aesKeySize, ivSize, hmacKeySize, tagSize) {
    // Define AES CTR key format.
    const aesCtrKeyFormat = new PbAesCtrKeyFormat();
    aesCtrKeyFormat.setKeySize(aesKeySize);
    aesCtrKeyFormat.setParams(new PbAesCtrParams());
    aesCtrKeyFormat.getParams().setIvSize(ivSize);

    // Define HMAC key format.
    const hmacKeyFormat = new PbHmacKeyFormat();
    hmacKeyFormat.setKeySize(hmacKeySize);
    hmacKeyFormat.setParams(new PbHmacParams());
    hmacKeyFormat.getParams().setTagSize(tagSize);
    hmacKeyFormat.getParams().setHash(PbHashType.SHA256);

    // Define AES CTR HMAC AEAD key format.
    const keyFormat = new PbAesCtrHmacAeadKeyFormat();
    keyFormat.setAesCtrKeyFormat(aesCtrKeyFormat);
    keyFormat.setHmacKeyFormat(hmacKeyFormat);

    // Define key template.
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL);
    keyTemplate.setOutputPrefixType(PbOutputPrefixType.TINK);
    keyTemplate.setValue(keyFormat.serializeBinary());

    return keyTemplate;
  }

  /**
   * @private
   *
   * @param {number} keySize
   *
   * @return {!PbKeyTemplate}
   */
  static newAesGcmKeyTemplate_(keySize) {
    // Define AES GCM key format.
    const keyFormat = new PbAesGcmKeyFormat();
    keyFormat.setKeySize(keySize);

    // Define key template.
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(AeadConfig.AES_GCM_TYPE_URL);
    keyTemplate.setOutputPrefixType(PbOutputPrefixType.TINK);
    keyTemplate.setValue(keyFormat.serializeBinary());

    return keyTemplate;
  }
}

exports = AeadKeyTemplates;
