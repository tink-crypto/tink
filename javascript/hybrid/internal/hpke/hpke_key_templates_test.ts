/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeKeyFormat, PbKeyTemplate, PbOutputPrefixType} from '../../../internal/proto';
import {bytesAsU8} from '../../../internal/proto_shims';

import * as hpkeKeyTemplates from './hpke_key_templates';
import {HpkePrivateKeyManager} from './hpke_private_key_manager';

interface TestVector {
  name: string;
  kem: PbHpkeKem;
  kdf: PbHpkeKdf;
  aead: PbHpkeAead;
  outputPrefix: PbOutputPrefixType;
  keyTemplate: PbKeyTemplate;
}

/** Test vectors for HPKE key templates. */
const TEST_VECTORS: TestVector[] = [
  /**
   * Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, RAW
   */
  {
    name: 'hpkeP256HkdfSha256Aes128GcmRaw',
    kem: PbHpkeKem.DHKEM_P256_HKDF_SHA256,
    kdf: PbHpkeKdf.HKDF_SHA256,
    aead: PbHpkeAead.AES_128_GCM,
    outputPrefix: PbOutputPrefixType.RAW,
    keyTemplate: hpkeKeyTemplates.hpkeP256HkdfSha256Aes128GcmRaw()
  },
  /**
   * Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, TINK
   */
  {
    name: 'hpkeP256HkdfSha256Aes128Gcm',
    kem: PbHpkeKem.DHKEM_P256_HKDF_SHA256,
    kdf: PbHpkeKdf.HKDF_SHA256,
    aead: PbHpkeAead.AES_128_GCM,
    outputPrefix: PbOutputPrefixType.TINK,
    keyTemplate: hpkeKeyTemplates.hpkeP256HkdfSha256Aes128Gcm()
  },
  /**
   * Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, RAW
   */
  {
    name: 'hpkeP256HkdfSha256Aes256GcmRaw',
    kem: PbHpkeKem.DHKEM_P256_HKDF_SHA256,
    kdf: PbHpkeKdf.HKDF_SHA256,
    aead: PbHpkeAead.AES_256_GCM,
    outputPrefix: PbOutputPrefixType.RAW,
    keyTemplate: hpkeKeyTemplates.hpkeP256HkdfSha256Aes256GcmRaw()
  },
  /**
   * Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, TINK
   */
  {
    name: 'hpkeP256HkdfSha256Aes256Gcm',
    kem: PbHpkeKem.DHKEM_P256_HKDF_SHA256,
    kdf: PbHpkeKdf.HKDF_SHA256,
    aead: PbHpkeAead.AES_256_GCM,
    outputPrefix: PbOutputPrefixType.TINK,
    keyTemplate: hpkeKeyTemplates.hpkeP256HkdfSha256Aes256Gcm()
  },
  /**
   * Test vector for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM, RAW
   */
  {
    name: 'hpkeP521HkdfSha512Aes256GcmRaw',
    kem: PbHpkeKem.DHKEM_P521_HKDF_SHA512,
    kdf: PbHpkeKdf.HKDF_SHA512,
    aead: PbHpkeAead.AES_256_GCM,
    outputPrefix: PbOutputPrefixType.RAW,
    keyTemplate: hpkeKeyTemplates.hpkeP521HkdfSha512Aes256GcmRaw()
  },
  /**
   * Test vector for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM, TINK
   */
  {
    name: 'hpkeP521HkdfSha512Aes256Gcm',
    kem: PbHpkeKem.DHKEM_P521_HKDF_SHA512,
    kdf: PbHpkeKdf.HKDF_SHA512,
    aead: PbHpkeAead.AES_256_GCM,
    outputPrefix: PbOutputPrefixType.TINK,
    keyTemplate: hpkeKeyTemplates.hpkeP521HkdfSha512Aes256Gcm()
  },
];

describe('hpke key templates test', () => {
  const manager = new HpkePrivateKeyManager();
  // Expected type URL is the one supported by HpkePrivateKeyManager.
  const expectedTypeUrl = manager.getKeyType();

  for (const testInfo of TEST_VECTORS) {
    it(testInfo.name +
           ' key template should have the expected values and work with the' +
           ' key manager',
       () => {
         expect(testInfo.keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
         expect(testInfo.keyTemplate.getOutputPrefixType())
             .toBe(testInfo.outputPrefix);

         // Test values in key format.
         const keyFormat =
             PbHpkeKeyFormat.deserializeBinary(testInfo.keyTemplate.getValue());
         const params = keyFormat.getParams();

         expect(params!.getKem()).toBe(testInfo.kem);
         expect(params!.getKdf()).toBe(testInfo.kdf);
         expect(params!.getAead()).toBe(testInfo.aead);

         // Test that the template works with HpkePrivateKeyManager.
         manager.getKeyFactory().newKey(
             bytesAsU8(testInfo.keyTemplate.getValue()));
       });
  }
});
