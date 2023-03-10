/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {KeysetHandle} from '../../../internal/keyset_handle';
import {PbKeyData, PbKeyset, PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../../../internal/proto';
import {bytesAsU8} from '../../../internal/proto_shims';
import * as registry from '../../../internal/registry';
import * as random from '../../../subtle/random';
import {HybridDecrypt} from '../../internal/hybrid_decrypt';
import {HybridEncrypt} from '../../internal/hybrid_encrypt';

import * as hpke from './index';


describe(
    'hpke encrypting and decrypting test using predefined key templates',
    () => {
      // Check that everything was registered correctly and thus new keys may be
      // generated using the predefined key templates and then they may be used
      // for encryption and decryption.
      it('register, predefined templates should work', async () => {
        hpke.register();

        const templates = [
          hpke.hpkeP256HkdfSha256Aes128GcmRawKeyTemplate,
          hpke.hpkeP256HkdfSha256Aes128GcmKeyTemplate,
          hpke.hpkeP256HkdfSha256Aes256GcmRawKeyTemplate,
          hpke.hpkeP256HkdfSha256Aes256GcmKeyTemplate,
          hpke.hpkeP521HkdfSha512Aes256GcmRawKeyTemplate,
          hpke.hpkeP521HkdfSha512Aes256GcmKeyTemplate
        ];
        for (const template of templates) {
          const privateKeyData = await registry.newKeyData(template);
          const privateKeysetHandle =
              createKeysetHandleFromKeyData(privateKeyData);
          const hybridDecrypt =
              await privateKeysetHandle.getPrimitive<HybridDecrypt>(
                  HybridDecrypt);

          const publicKeyData = registry.getPublicKeyData(
              privateKeyData.getTypeUrl(),
              bytesAsU8(privateKeyData.getValue()));
          const publicKeysetHandle =
              createKeysetHandleFromKeyData(publicKeyData);
          const hybridEncrypt =
              await publicKeysetHandle.getPrimitive<HybridEncrypt>(
                  HybridEncrypt);

          const plaintext = new Uint8Array(random.randBytes(10));
          const contextInfo = new Uint8Array(random.randBytes(8));
          const ciphertext =
              await hybridEncrypt.encrypt(plaintext, contextInfo);
          const decryptedCiphertext =
              await hybridDecrypt.decrypt(ciphertext, contextInfo);

          expect(decryptedCiphertext).toEqual(plaintext);
        }
      });
    });

/**
 * Creates a keyset containing only the key given by keyData and returns it
 * wrapped in a KeysetHandle.
 */
function createKeysetHandleFromKeyData(keyData: PbKeyData): KeysetHandle {
  const keyId = 1;
  const key = new PbKeysetKey()
                  .setKeyData(keyData)
                  .setStatus(PbKeyStatusType.ENABLED)
                  .setKeyId(keyId)
                  .setOutputPrefixType(PbOutputPrefixType.TINK);

  const keyset = new PbKeyset();
  keyset.addKey(key);
  keyset.setPrimaryKeyId(keyId);
  return new KeysetHandle(keyset);
}
