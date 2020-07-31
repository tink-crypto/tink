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

import {PbAesCtrHmacAeadKeyFormat, PbAesCtrKeyFormat, PbAesCtrParams, PbHashType, PbHmacKeyFormat, PbHmacParams, PbKeyTemplate, PbOutputPrefixType} from '../internal/proto';

import {AesCtrHmacAeadKeyManager} from './aes_ctr_hmac_aead_key_manager';

/**
 * Pre-generated KeyTemplates for AES CTR HMAC AEAD keys.
 *
 * @final
 */
export class AesCtrHmacAeadKeyTemplates {
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
   */
  static aes128CtrHmacSha256(): PbKeyTemplate {
    return AesCtrHmacAeadKeyTemplates.newAesCtrHmacSha256KeyTemplate_(
        16,
        /* aesKeySize = */
        16,
        /* ivSize = */
        32,
        /* hmacKeySize = */
        16);
  }

  /* tagSize = */
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
   */
  static aes256CtrHmacSha256(): PbKeyTemplate {
    return AesCtrHmacAeadKeyTemplates.newAesCtrHmacSha256KeyTemplate_(
        32,
        /* aesKeySize = */
        16,
        /* ivSize = */
        32,
        /* hmacKeySize = */
        32);
  }

  /* tagSize = */
  private static newAesCtrHmacSha256KeyTemplate_(
      aesKeySize: number, ivSize: number, hmacKeySize: number,
      tagSize: number): PbKeyTemplate {
    // Define AES CTR key format.
    const aesCtrKeyFormat = (new PbAesCtrKeyFormat())
                                .setKeySize(aesKeySize)
                                .setParams(new PbAesCtrParams());
    aesCtrKeyFormat.getParams()!.setIvSize(ivSize);

    // Define HMAC key format.
    const hmacKeyFormat = (new PbHmacKeyFormat())
                              .setKeySize(hmacKeySize)
                              .setParams(new PbHmacParams());
    hmacKeyFormat.getParams()!.setTagSize(tagSize);
    hmacKeyFormat.getParams()!.setHash(PbHashType.SHA256);

    // Define AES CTR HMAC AEAD key format.
    const keyFormat = (new PbAesCtrHmacAeadKeyFormat())
                          .setAesCtrKeyFormat(aesCtrKeyFormat)
                          .setHmacKeyFormat(hmacKeyFormat);

    // Define key template.
    const keyTemplate = (new PbKeyTemplate())
                            .setTypeUrl(AesCtrHmacAeadKeyManager.KEY_TYPE)
                            .setOutputPrefixType(PbOutputPrefixType.TINK)
                            .setValue(keyFormat.serializeBinary());
    return keyTemplate;
  }
}
