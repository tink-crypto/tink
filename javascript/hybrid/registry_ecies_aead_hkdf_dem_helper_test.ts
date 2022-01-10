/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../aead/aead_config';
import {AeadKeyTemplates} from '../aead/aead_key_templates';
import * as Registry from '../internal/registry';
import * as Random from '../subtle/random';

import {RegistryEciesAeadHkdfDemHelper} from './registry_ecies_aead_hkdf_dem_helper';

describe('registry ecies aead hkdf dem helper test', function() {
  beforeEach(function() {
    AeadConfig.register();
  });

  afterEach(function() {
    Registry.reset();
  });

  //////////////////////////////////////////////////////////////////////////////
  // Tests for constructor
  //////////////////////////////////////////////////////////////////////////////

  it('constructor, unsupported key type', function() {
    const template = AeadKeyTemplates.aes128CtrHmacSha256().setTypeUrl(
        'some_unsupported_type_url');

    try {
      new RegistryEciesAeadHkdfDemHelper(template);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedTypeUrl(template.getTypeUrl()));
    }
  });

  it('constructor, invalid key formats', function() {
    // Some valid AES-GCM and AES-CTR-HMAC key templates.
    const templates =
        [AeadKeyTemplates.aes128CtrHmacSha256(), AeadKeyTemplates.aes128Gcm()];
    const invalidKeyFormats = [new Uint8Array(0), new Uint8Array([0, 1, 2])];

    // Test that if the value is changed to invalid key format than the DEM
    // helper throws an exception.
    for (const template of templates) {
      for (const invalidKeyFormat of invalidKeyFormats) {
        template.setValue(invalidKeyFormat);

        try {
          new RegistryEciesAeadHkdfDemHelper(template);
          fail('An exception should be thrown.');
        } catch (e: any) {
          expect(e.toString())
              .toBe(ExceptionText.invalidKeyFormat(template.getTypeUrl()));
        }
      }
    }
  });

  it('constructor, aes128 ctr hmac sha256 key template', function() {
    const template = AeadKeyTemplates.aes128CtrHmacSha256();
    const helper = new RegistryEciesAeadHkdfDemHelper(template);

    // Expected size is a sum of AES CTR key length and HMAC key length.
    const expectedSize = 16 + 32;
    expect(helper.getDemKeySizeInBytes()).toBe(expectedSize);
  });

  it('constructor, aes256 ctr hmac sha256 key template', function() {
    const template = AeadKeyTemplates.aes256CtrHmacSha256();
    const helper = new RegistryEciesAeadHkdfDemHelper(template);

    // Expected size is a sum of AES CTR key length and HMAC key length.
    const expectedSize = 32 + 32;
    expect(helper.getDemKeySizeInBytes()).toBe(expectedSize);
  });

  it('constructor, aes128 gcm', function() {
    const template = AeadKeyTemplates.aes128Gcm();
    const helper = new RegistryEciesAeadHkdfDemHelper(template);

    // Expected size is equal to the size of key.
    const expectedSize = 16;
    expect(helper.getDemKeySizeInBytes()).toBe(expectedSize);
  });

  it('constructor, aes256 gcm', function() {
    const template = AeadKeyTemplates.aes256Gcm();
    const helper = new RegistryEciesAeadHkdfDemHelper(template);

    // Expected size is equal to the size of key.
    const expectedSize = 32;
    expect(helper.getDemKeySizeInBytes()).toBe(expectedSize);
  });

  //////////////////////////////////////////////////////////////////////////////
  // Tests for getAead method
  //////////////////////////////////////////////////////////////////////////////

  it('get aead, invalid key length', async function() {
    const template = AeadKeyTemplates.aes128CtrHmacSha256();
    // Expected size is a sum of AES CTR key length and HMAC key length.
    const expectedKeyLength = 16 + 32;
    const helper = new RegistryEciesAeadHkdfDemHelper(template);
    const keyLength = 2;

    try {
      await helper.getAead(new Uint8Array(keyLength));
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.invalidKeyLength(expectedKeyLength, keyLength));
    }
  });

  it('get aead, different templates', async function() {
    const templates = [
      AeadKeyTemplates.aes128CtrHmacSha256(), AeadKeyTemplates.aes128Gcm(),
      AeadKeyTemplates.aes256CtrHmacSha256(), AeadKeyTemplates.aes256Gcm()
    ];

    for (const template of templates) {
      const helper = new RegistryEciesAeadHkdfDemHelper(template);
      // Compute some demKey of size corresponding to the template.
      // The result of getDemKeySizeInBytes is the expected one for the given
      // templates as it was tested for these templates in previous tests.
      const demKey = Random.randBytes(helper.getDemKeySizeInBytes());

      // Get Aead from helper.
      const aead = await helper.getAead(demKey);
      expect(aead != null).toBe(true);

      // Test the Aead instance.
      const plaintext = Random.randBytes(10);
      const aad = Random.randBytes(10);
      const ciphertext = await aead.encrypt(plaintext, aad);
      const decryptedCiphertext = await aead.decrypt(ciphertext, aad);

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });
});

// Helper classes and functions
class ExceptionText {
  static unsupportedTypeUrl(typeUrl: string): string {
    return 'SecurityException: Key type URL ' + typeUrl + ' is not supported.';
  }

  static invalidKeyFormat(keyType: string): string {
    return 'SecurityException: Could not parse the given Uint8Array as ' +
        'a serialized proto of ' + keyType + '.';
  }

  static invalidKeyLength(expectedKeyLength: number, actualKeyLength: number):
      string {
    return 'SecurityException: Key is not of the correct length, expected length: ' +
        expectedKeyLength + ', but got key of length: ' + actualKeyLength + '.';
  }
}
