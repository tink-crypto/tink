/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {KeysetHandle} from '../internal/keyset_handle';
import {PbKeyData, PbKeyset, PbKeysetKey, PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import {bytesAsU8} from '../internal/proto_shims';
import * as registry from '../internal/registry';
import * as random from '../subtle/random';

import {EciesAeadHkdfPrivateKeyManager} from './ecies_aead_hkdf_private_key_manager';
import {EciesAeadHkdfPublicKeyManager} from './ecies_aead_hkdf_public_key_manager';
import * as hybridConfig from './hybrid_config';
import {HybridKeyTemplates} from './hybrid_key_templates';
import * as hpkeKeyTemplates from './internal/hpke/hpke_key_templates';
import {HpkePrivateKeyManager} from './internal/hpke/hpke_private_key_manager';
import {HpkePublicKeyManager} from './internal/hpke/hpke_public_key_manager';
import {HybridDecrypt} from './internal/hybrid_decrypt';
import {HybridEncrypt} from './internal/hybrid_encrypt';

describe('hybrid config test', () => {
  beforeEach(() => {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(() => {
    registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('constants', () => {
    expect(hybridConfig.ENCRYPT_PRIMITIVE_NAME).toBe(ENCRYPT_PRIMITIVE_NAME);
    expect(hybridConfig.DECRYPT_PRIMITIVE_NAME).toBe(DECRYPT_PRIMITIVE_NAME);

    expect(hybridConfig.ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE)
        .toBe(ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE);
    expect(hybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE)
        .toBe(ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE);

    expect(hybridConfig.HPKE_PUBLIC_KEY_TYPE).toBe(HPKE_PUBLIC_KEY_TYPE);
    expect(hybridConfig.HPKE_PRIVATE_KEY_TYPE).toBe(HPKE_PRIVATE_KEY_TYPE);
  });

  it('register, correct key managers were registered', () => {
    hybridConfig.register();

    // Test that the corresponding key managers were registered.
    const eciesAeadHkdfPublicKeyManager =
        registry.getKeyManager(ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE);
    expect(
        eciesAeadHkdfPublicKeyManager instanceof EciesAeadHkdfPublicKeyManager)
        .toBe(true);

    const eciesAeadHkdfPrivateKeyManager =
        registry.getKeyManager(ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE);
    expect(
        eciesAeadHkdfPrivateKeyManager instanceof
        EciesAeadHkdfPrivateKeyManager)
        .toBe(true);

    const hpkePublicKeyManager = registry.getKeyManager(HPKE_PUBLIC_KEY_TYPE);
    expect(hpkePublicKeyManager instanceof HpkePublicKeyManager).toBe(true);

    const hpkePrivateKeyManager = registry.getKeyManager(HPKE_PRIVATE_KEY_TYPE);
    expect(hpkePrivateKeyManager instanceof HpkePrivateKeyManager).toBe(true);
  });

  // Check that everything was registered correctly and thus new keys may be
  // generated using the predefined key templates and then they may be used for
  // encryption and decryption.
  it('register, predefined templates should work', async () => {
    hybridConfig.register();
    const templates = [
      HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm(),
      HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128CtrHmacSha256(),
      hpkeKeyTemplates.hpkeP256HkdfSha256Aes128GcmRaw(),
      hpkeKeyTemplates.hpkeP256HkdfSha256Aes128Gcm(),
      hpkeKeyTemplates.hpkeP256HkdfSha256Aes256GcmRaw(),
      hpkeKeyTemplates.hpkeP256HkdfSha256Aes256Gcm(),
      hpkeKeyTemplates.hpkeP521HkdfSha512Aes256GcmRaw(),
      hpkeKeyTemplates.hpkeP521HkdfSha512Aes256Gcm()
    ];
    for (const template of templates) {
      const privateKeyData = await registry.newKeyData(template);
      const privateKeysetHandle = createKeysetHandleFromKeyData(privateKeyData);
      const hybridDecrypt =
          await privateKeysetHandle.getPrimitive<HybridDecrypt>(HybridDecrypt);

      const publicKeyData = registry.getPublicKeyData(
          privateKeyData.getTypeUrl(), bytesAsU8(privateKeyData.getValue()));
      const publicKeysetHandle = createKeysetHandleFromKeyData(publicKeyData);
      const hybridEncrypt =
          await publicKeysetHandle.getPrimitive<HybridEncrypt>(HybridEncrypt);

      const plaintext = new Uint8Array(random.randBytes(10));
      const contextInfo = new Uint8Array(random.randBytes(8));
      const ciphertext = await hybridEncrypt.encrypt(plaintext, contextInfo);
      const decryptedCiphertext =
          await hybridDecrypt.decrypt(ciphertext, contextInfo);

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });
});

// Constants used in tests.
const ENCRYPT_PRIMITIVE_NAME = 'HybridEncrypt';
const DECRYPT_PRIMITIVE_NAME = 'HybridDecrypt';
const ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
const ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey';
const HPKE_PUBLIC_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.HpkePublicKey';
const HPKE_PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.HpkePrivateKey';

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
