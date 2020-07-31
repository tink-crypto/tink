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

import {PbKeyTemplate} from '../internal/proto';

import {AesCtrHmacAeadKeyTemplates} from './aes_ctr_hmac_aead_key_templates';
import {AesGcmKeyTemplates} from './aes_gcm_key_templates';

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
export class AeadKeyTemplates {
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
   */
  static aes256CtrHmacSha256(): PbKeyTemplate {
    return AesCtrHmacAeadKeyTemplates.aes256CtrHmacSha256();
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 16 bytes
   *    OutputPrefixType: TINK
   *
   */
  static aes128Gcm(): PbKeyTemplate {
    return AesGcmKeyTemplates.aes128Gcm();
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 32 bytes
   *    OutputPrefixType: TINK
   *
   */
  static aes256Gcm(): PbKeyTemplate {
    return AesGcmKeyTemplates.aes256Gcm();
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *     key size: 32 bytes
   *     OutputPrefixType: RAW
   *
   */
  static aes256GcmNoPrefix(): PbKeyTemplate {
    return AesGcmKeyTemplates.aes256GcmNoPrefix();
  }
}
