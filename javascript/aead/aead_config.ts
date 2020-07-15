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

import {AeadWrapper} from './aead_wrapper';
import {AesCtrHmacAeadKeyManager} from './aes_ctr_hmac_aead_key_manager';
import {AesGcmKeyManager} from './aes_gcm_key_manager';

/**
 * Static methods and constants for registering with the Registry all instances
 * of Aead key types supported in a particular release of Tink.
 *
 * To register all Aead key types from the current Tink release one can do:
 *
 * AeadConfig.register();
 *
 * For more information on creation and usage of Aead instances see AeadFactory.
 *
 * @final
 */
export class AeadConfig {
  private static readonly CONFIG_NAME_: string = 'TINK_AEAD';
  static PRIMITIVE_NAME: string = 'Aead';
  static AES_CTR_HMAC_AEAD_TYPE_URL: string;
  static AES_GCM_TYPE_URL: string;

  /**
   * Registers key managers for all Aead key types from the current Tink
   * release.
   */
  static register() {
    // TODO MacConfig.register() should be here.
    AesGcmKeyManager.register();
    AesCtrHmacAeadKeyManager.register();
    AeadWrapper.register();
  }
}
AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL = AesCtrHmacAeadKeyManager.KEY_TYPE;
AeadConfig.AES_GCM_TYPE_URL = AesGcmKeyManager.KEY_TYPE;
