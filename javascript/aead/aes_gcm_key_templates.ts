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

import {PbAesGcmKeyFormat, PbKeyTemplate, PbOutputPrefixType} from '../internal/proto';

import {AesGcmKeyManager} from './aes_gcm_key_manager';

/**
 * Pre-generated KeyTemplates for AES GCM keys.
 *
 * @final
 */
export class AesGcmKeyTemplates {
  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 16 bytes
   *    OutputPrefixType: TINK
   *
   */
  static aes128Gcm(): PbKeyTemplate {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate_(
        /* keySize = */
        16,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *    key size: 32 bytes
   *    OutputPrefixType: TINK
   *
   */
  static aes256Gcm(): PbKeyTemplate {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate_(
        /* keySize = */
        32,
        /* outputPrefixType = */
        PbOutputPrefixType.TINK);
  }

  /**
   * Returns a KeyTemplate that generates new instances of AesGcmKey
   * with the following parameters:
   *     key size: 32 bytes
   *     OutputPrefixType: RAW
   *
   */
  static aes256GcmNoPrefix(): PbKeyTemplate {
    return AesGcmKeyTemplates.newAesGcmKeyTemplate_(
        /* keySize = */
        32,
        /* outputPrefixType = */
        PbOutputPrefixType.RAW);
  }

  private static newAesGcmKeyTemplate_(
      keySize: number, outputPrefixType: PbOutputPrefixType): PbKeyTemplate {
    // Define AES GCM key format.
    const keyFormat = (new PbAesGcmKeyFormat()).setKeySize(keySize);

    // Define key template.
    const keyTemplate = (new PbKeyTemplate())
                            .setTypeUrl(AesGcmKeyManager.KEY_TYPE)
                            .setOutputPrefixType(outputPrefixType)
                            .setValue(keyFormat.serializeBinary());
    return keyTemplate;
  }
}
