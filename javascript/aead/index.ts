import * as aesCtrHmac from './aes_ctr_hmac';
import * as aesGcm from './aes_gcm';
import * as wrapper from './wrapper';

export * from './aead';
export * from './aes_ctr_hmac';
export {aes128GcmKeyTemplate, aes256GcmKeyTemplate, aes256GcmNoPrefixKeyTemplate} from './aes_gcm';

export function register() {
  aesCtrHmac.register();
  aesGcm.register();
  wrapper.register();
}
