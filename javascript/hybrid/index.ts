import * as aesCtrHmac from '../aead/aes_ctr_hmac';
import * as aesGcm from '../aead/aes_gcm';
import * as decryptWrapper from './decrypt_wrapper';
import * as eciesAeadHkdfForDecrypting from './ecies_aead_hkdf_for_decrypting';
import * as eciesAeadHkdfForEncrypting from './ecies_aead_hkdf_for_encrypting';
import * as encryptWrapper from './encrypt_wrapper';

export * from './ecies_with_aes_ctr_hmac';
export * from './ecies_with_aes_gcm';
export * from './decrypt';
export * from './encrypt';

export function register() {
  aesCtrHmac.register();
  aesGcm.register();
  decryptWrapper.register();
  eciesAeadHkdfForDecrypting.register();
  eciesAeadHkdfForEncrypting.register();
  encryptWrapper.register();
}
