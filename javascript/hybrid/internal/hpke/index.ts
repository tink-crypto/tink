/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as aesGcm from '../../../aead/aes_gcm';
import * as hybridDecryptWrapper from '../../../hybrid/decrypt_wrapper';
import * as hybridEncryptWrapper from '../../../hybrid/encrypt_wrapper';

import * as hpkeForDecrypting from './hpke_for_decrypting';
import * as hpkeForEncrypting from './hpke_for_encrypting';

export {hpkeP256HkdfSha256Aes128GcmKeyTemplate, hpkeP256HkdfSha256Aes128GcmRawKeyTemplate, hpkeP256HkdfSha256Aes256GcmKeyTemplate, hpkeP256HkdfSha256Aes256GcmRawKeyTemplate, hpkeP521HkdfSha512Aes256GcmKeyTemplate, hpkeP521HkdfSha512Aes256GcmRawKeyTemplate} from './hpke_for_decrypting';

export * from '../../../hybrid/decrypt';
export * from '../../../hybrid/encrypt';

/** Registers wrappers and HPKE key managers */
export function register() {
  aesGcm.register();
  hybridDecryptWrapper.register();
  hpkeForDecrypting.register();
  hpkeForEncrypting.register();
  hybridEncryptWrapper.register();
}
