/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbHashType, PbHmacKeyFormat, PbKeyTemplate, PbOutputPrefixType} from '../internal/proto';
import {bytesAsU8, bytesLength} from '../internal/proto_shims';

import {HmacKeyManager} from './hmac_key_manager';
import * as macKeyTemplates from './mac_key_templates';

interface TestVector {
  name: string;
  keySize: number;
  tagSize: number;
  hashType: PbHashType;
  outputPrefix: PbOutputPrefixType;
  keyTemplate: PbKeyTemplate;
}

/** Test vectors for HMAC key templates. */
const TEST_VECTORS: TestVector[] = [
  /**
   * Test vector for HMAC with SHA256 and 128 bit tag
   */
  {
    name: 'hmacSha256Tag128',
    keySize: 32,
    tagSize: 16,
    hashType: PbHashType.SHA256,
    outputPrefix: PbOutputPrefixType.TINK,
    keyTemplate: macKeyTemplates.hmacSha256Tag128()
  },
  /**
   * Test vector for HMAC with SHA256 and 256 bit tag
   */
  {
    name: 'hmacSha256Tag256',
    keySize: 32,
    tagSize: 32,
    hashType: PbHashType.SHA256,
    outputPrefix: PbOutputPrefixType.TINK,
    keyTemplate: macKeyTemplates.hmacSha256Tag256()
  },
  /**
   * Test vector for HMAC with SHA512 and 256 bit tag
   */
  {
    name: 'hmacSha512Tag256',
    keySize: 64,
    tagSize: 32,
    hashType: PbHashType.SHA512,
    outputPrefix: PbOutputPrefixType.TINK,
    keyTemplate: macKeyTemplates.hmacSha512Tag256()
  },
  /**
   * Test vector for HMAC with SHA512 and 512 bit tag
   */
  {
    name: 'hmacSha512Tag512',
    keySize: 64,
    tagSize: 64,
    hashType: PbHashType.SHA512,
    outputPrefix: PbOutputPrefixType.TINK,
    keyTemplate: macKeyTemplates.hmacSha512Tag512()
  }
];

describe('hmac key templates test', () => {
  const manager = new HmacKeyManager();
  // The expected type URL is the one supported by the HmacKeyManager.
  const expectedTypeUrl = manager.getKeyType();

  for (const testInfo of TEST_VECTORS) {
    it(testInfo.name +
           ' key template should have the expected values and work with the' +
           ' key manager',
       () => {
         expect(testInfo.keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
         expect(testInfo.keyTemplate.getOutputPrefixType())
             .toBe(testInfo.outputPrefix);

         // Get the key format and test the values.
         const keyFormat =
             PbHmacKeyFormat.deserializeBinary(testInfo.keyTemplate.getValue());

         expect(keyFormat.getKeySize()).toBe(testInfo.keySize);
         expect(keyFormat.getParams()!.getHash()).toBe(testInfo.hashType);
         expect(keyFormat.getParams()!.getTagSize()).toBe(testInfo.tagSize);

         // Test that the template works with the key manager.
         const key = manager.getKeyFactory().newKey(
             bytesAsU8(testInfo.keyTemplate.getValue()));

         expect(bytesLength(key.getKeyValue())).toBe(keyFormat.getKeySize());
         expect(key.getParams()).toEqual(keyFormat.getParams());
       });
  }
});
