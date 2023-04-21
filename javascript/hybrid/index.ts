/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as aesCtrHmac from '../aead/aes_ctr_hmac';
import * as aesGcm from '../aead/aes_gcm';

import * as decryptWrapper from './decrypt_wrapper';
import * as eciesAeadHkdfForDecrypting from './ecies_aead_hkdf_for_decrypting';
import * as eciesAeadHkdfForEncrypting from './ecies_aead_hkdf_for_encrypting';
import * as encryptWrapper from './encrypt_wrapper';
import * as hpkeForDecrypting from './internal/hpke/hpke_for_decrypting';
import * as hpkeForEncrypting from './internal/hpke/hpke_for_encrypting';


export * from './ecies_with_aes_ctr_hmac';
export * from './ecies_with_aes_gcm';
export * from './decrypt';
export * from './encrypt';
export {hpkeP256HkdfSha256Aes128GcmKeyTemplate, hpkeP256HkdfSha256Aes128GcmRawKeyTemplate, hpkeP256HkdfSha256Aes256GcmKeyTemplate, hpkeP256HkdfSha256Aes256GcmRawKeyTemplate, hpkeP521HkdfSha512Aes256GcmKeyTemplate, hpkeP521HkdfSha512Aes256GcmRawKeyTemplate} from './internal/hpke/hpke_for_decrypting';

export function register() {
  aesCtrHmac.register();
  aesGcm.register();
  decryptWrapper.register();
  eciesAeadHkdfForDecrypting.register();
  eciesAeadHkdfForEncrypting.register();
  encryptWrapper.register();
  hpkeForDecrypting.register();
  hpkeForEncrypting.register();
}
