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

goog.module('tink.aead.AesCtrHmacAeadKeyTemplates');

const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbAesCtrParams = goog.require('proto.google.crypto.tink.AesCtrParams');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbHmacParams = goog.require('proto.google.crypto.tink.HmacParams');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');

/**
 * Pre-generated KeyTemplates for AES CTR HMAC AEAD keys.
 *
 * @final
 */
class AesCtrHmacAeadKeyTemplates {
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
    return AesCtrHmacAeadKeyTemplates.newAesCtrHmacSha256KeyTemplate_(
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
    return AesCtrHmacAeadKeyTemplates.newAesCtrHmacSha256KeyTemplate_(
        /* aesKeySize = */ 32,
        /* ivSize = */ 16,
        /* hmacKeySize = */ 32,
        /* tagSize = */ 32);
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
    const aesCtrKeyFormat = new PbAesCtrKeyFormat()
                                .setKeySize(aesKeySize)
                                .setParams(new PbAesCtrParams());
    aesCtrKeyFormat.getParams().setIvSize(ivSize);

    // Define HMAC key format.
    const hmacKeyFormat = new PbHmacKeyFormat()
                              .setKeySize(hmacKeySize)
                              .setParams(new PbHmacParams());
    hmacKeyFormat.getParams().setTagSize(tagSize);
    hmacKeyFormat.getParams().setHash(PbHashType.SHA256);

    // Define AES CTR HMAC AEAD key format.
    const keyFormat = new PbAesCtrHmacAeadKeyFormat()
                          .setAesCtrKeyFormat(aesCtrKeyFormat)
                          .setHmacKeyFormat(hmacKeyFormat);

    // Define key template.
    const keyTemplate = new PbKeyTemplate()
                            .setTypeUrl(AesCtrHmacAeadKeyManager.KEY_TYPE)
                            .setOutputPrefixType(PbOutputPrefixType.TINK)
                            .setValue(keyFormat.serializeBinary());

    return keyTemplate;
  }
}

exports = AesCtrHmacAeadKeyTemplates;
