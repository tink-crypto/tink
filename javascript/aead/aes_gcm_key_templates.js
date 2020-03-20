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

goog.module('tink.aead.AesGcmKeyTemplates');

const AesGcmKeyManager = goog.require('tink.aead.AesGcmKeyManager');
const {PbAesGcmKeyFormat, PbKeyTemplate, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

/**
 * Pre-generated KeyTemplates for AES GCM keys.
 *
 * @final
 */
class AesGcmKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 16 bytes
   *    OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static aes128Gcm() {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate_(
        /* keySize = */ 16,
        /* outputPrefixType = */ PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 32 bytes
   *    OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static aes256Gcm() {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate_(
        /* keySize = */ 32,
        /* outputPrefixType = */ PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *     key size: 32 bytes
   *     OutputPrefixType: RAW
   *
   * @return {!PbKeyTemplate}
   */
  static aes256GcmNoPrefix() {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate_(
        /* keySize = */ 32,
        /* outputPrefixType = */ PbOutputPrefixType.RAW);
  }

  /**
   * @private
   *
   * @param {number} keySize
   * @param {!PbOutputPrefixType} outputPrefixType
   *
   * @return {!PbKeyTemplate}
   */
  static newAesGcmKeyTemplate_(keySize, outputPrefixType) {
    // Define AES GCM key format.
    const keyFormat = new PbAesGcmKeyFormat().setKeySize(keySize);

    // Define key template.
    const keyTemplate = new PbKeyTemplate()
                            .setTypeUrl(AesGcmKeyManager.KEY_TYPE)
                            .setOutputPrefixType(outputPrefixType)
                            .setValue(keyFormat.serializeBinary());

    return keyTemplate;
  }
}

exports = AesGcmKeyTemplates;
