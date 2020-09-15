/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

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
