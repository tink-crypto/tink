/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {KeysetHandle} from '../internal/keyset_handle';
import {PbKeyData, PbKeyset, PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import * as Registry from '../internal/registry';
import * as Random from '../subtle/random';

import {AeadConfig} from './aead_config';
import {AeadKeyTemplates} from './aead_key_templates';
import {AesCtrHmacAeadKeyManager} from './aes_ctr_hmac_aead_key_manager';
import {AesGcmKeyManager} from './aes_gcm_key_manager';
import {Aead} from './internal/aead';

describe('aead config test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    Registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('constants', function() {
    expect(AeadConfig.PRIMITIVE_NAME).toBe(PRIMITIVE_NAME);

    expect(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL)
        .toBe(AES_CTR_HMAC_AEAD_KEY_TYPE);
    expect(AeadConfig.AES_GCM_TYPE_URL).toBe(AES_GCM_KEY_TYPE);
  });

  it('register, corresponding key managers were registered', function() {
    AeadConfig.register();

    // Test that the corresponding key managers were registered.
    const aesCtrHmacKeyManager =
        Registry.getKeyManager(AES_CTR_HMAC_AEAD_KEY_TYPE);
    expect(aesCtrHmacKeyManager instanceof AesCtrHmacAeadKeyManager).toBe(true);

    const aesGcmKeyManager = Registry.getKeyManager(AES_GCM_KEY_TYPE);
    expect(aesGcmKeyManager instanceof AesGcmKeyManager).toBe(true);

    // TODO add tests for other key types here, whenever they are available in
    // Tink.
  });

  it('register, predefined templates should work', async function() {
    AeadConfig.register();
    let templates = [
      AeadKeyTemplates.aes128Gcm(), AeadKeyTemplates.aes256Gcm(),
      AeadKeyTemplates.aes128CtrHmacSha256(),
      AeadKeyTemplates.aes256CtrHmacSha256()
    ];
    for (const template of templates) {
      const keyData = await Registry.newKeyData(template);
      const keysetHandle = createKeysetHandleFromKeyData(keyData);

      const aead = await keysetHandle.getPrimitive<Aead>(Aead);
      const plaintext = Random.randBytes(10);
      const aad = Random.randBytes(8);
      const ciphertext = await aead.encrypt(plaintext, aad);
      const decryptedCiphertext = await aead.decrypt(ciphertext, aad);

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });
});

// Constants used in tests.
const PRIMITIVE_NAME = 'Aead';
const AES_CTR_HMAC_AEAD_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
const AES_GCM_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesGcmKey';

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
