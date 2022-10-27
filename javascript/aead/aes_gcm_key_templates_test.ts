/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbAesGcmKeyFormat, PbOutputPrefixType} from '../internal/proto';
import {bytesAsU8} from '../internal/proto_shims';

import {AesGcmKeyManager} from './aes_gcm_key_manager';
import {AesGcmKeyTemplates} from './aes_gcm_key_templates';

describe('aes gcm key templates test', function() {
  it('aes128 gcm', function() {
    // The created key should have the following parameters.
    const expectedKeySize = 16;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes128Gcm();

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue());
    expect(keyFormat.getKeySize()).toBe(expectedKeySize);

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(bytesAsU8(keyTemplate.getValue()));
  });

  it('aes256 gcm', function() {
    // The created key should have the following parameters.
    const expectedKeySize = 32;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes256Gcm();

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue());
    expect(keyFormat.getKeySize()).toBe(expectedKeySize);

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(bytesAsU8(keyTemplate.getValue()));
  });

  it('aes256 gcm no prefix', function() {
    // The created key should have the following parameters.
    const expectedKeySize = 32;
    const expectedOutputPrefix = PbOutputPrefixType.RAW;
    // Expected type URL is the one supported by AesGcmKeyManager.
    const manager = new AesGcmKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = AesGcmKeyTemplates.aes256GcmNoPrefix();

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test key size value in key format.
    const keyFormat =
        PbAesGcmKeyFormat.deserializeBinary(keyTemplate.getValue());
    expect(keyFormat.getKeySize()).toBe(expectedKeySize);

    // Test that the template works with AesCtrHmacAeadKeyManager.
    manager.getKeyFactory().newKey(bytesAsU8(keyTemplate.getValue()));
  });
});
