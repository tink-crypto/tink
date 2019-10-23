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

const AesCtrHmacAeadKeyTemplates = goog.require('tink.aead.AesCtrHmacAeadKeyTemplates');
const AesGcmKeyTemplates = goog.require('tink.aead.AesGcmKeyTemplates');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');

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
    return AesCtrHmacAeadKeyTemplates.aes128CtrHmacSha256();
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
    return AesCtrHmacAeadKeyTemplates.aes256CtrHmacSha256();
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 16 bytes
   *    OutputPrefixType: TINK
   *
   * @return {!PbKeyTemplate}
   */
  static aes128Gcm() {
    return AesGcmKeyTemplates.aes128Gcm();
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
    return AesGcmKeyTemplates.aes256Gcm();
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
    return AesGcmKeyTemplates.aes256GcmNoPrefix();
  }
}

exports = AeadKeyTemplates;
