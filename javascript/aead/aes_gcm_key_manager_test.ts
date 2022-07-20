/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbAesCtrKey, PbAesCtrKeyFormat, PbAesGcmKey, PbAesGcmKeyFormat, PbKeyData} from '../internal/proto';
import * as Random from '../subtle/random';

import {AesGcmKeyManager} from './aes_gcm_key_manager';
import {Aead} from './internal/aead';

const KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesGcmKey';
const VERSION = 0;
const PRIMITIVE = Aead;

describe('aes gcm key manager test', function() {
  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method

  // newKey method -- key formats
  it('new key, invalid key format', function() {
    const keyFormat = new PbAesCtrKeyFormat();
    const manager = new AesGcmKeyManager();

    try {
      manager.getKeyFactory().newKey(keyFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.invalidKeyFormat());
    }
  });

  it('new key, invalid serialized key format', function() {
    const keyFormat = new Uint8Array(0);
    const manager = new AesGcmKeyManager();

    try {
      manager.getKeyFactory().newKey(keyFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
    }
  });

  it('new key, unsupported key sizes', function() {
    const manager = new AesGcmKeyManager();

    for (let keySize = 0; keySize < 40; keySize++) {
      if (keySize === 16 || keySize === 32) {
        // Keys of size 16 and 32 bytes are supported.
        continue;
      }
      const keyFormat = createTestKeyFormat(keySize);

      try {
        manager.getKeyFactory().newKey(keyFormat);
        fail('An exception should be thrown.');
      } catch (e: any) {
        expect(e.toString()).toBe(ExceptionText.unsupportedKeySize(keySize));
      }
    }
  });

  it('new key, via format proto', function() {
    const manager = new AesGcmKeyManager();

    const keyFormat = createTestKeyFormat();

    const key = manager.getKeyFactory().newKey(keyFormat);

    expect(key.getKeyValue_asU8().length).toBe(keyFormat.getKeySize());
  });

  it('new key, via serialized format proto', function() {
    const manager = new AesGcmKeyManager();

    const keyFormat = createTestKeyFormat();
    const serializedKeyFormat = keyFormat.serializeBinary();

    const key = manager.getKeyFactory().newKey(serializedKeyFormat);

    expect(key.getKeyValue_asU8().length).toBe(keyFormat.getKeySize());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for NewKeyData method

  it('new key data, should work', function() {
    const keyFormat = createTestKeyFormat();
    const serializedKeyFormat = keyFormat.serializeBinary();
    const manager = new AesGcmKeyManager();

    const keyData = manager.getKeyFactory().newKeyData(serializedKeyFormat);

    expect(keyData.getTypeUrl()).toBe(KEY_TYPE);
    expect(keyData.getKeyMaterialType())
        .toBe(PbKeyData.KeyMaterialType.SYMMETRIC);

    const key = PbAesGcmKey.deserializeBinary(keyData.getValue_asU8());

    expect(key.getKeyValue_asU8().length).toBe(keyFormat.getKeySize());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method

  it('get primitive, unsupported key data type', async function() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData().setTypeUrl('bad_type_url');

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyType(keyData.getTypeUrl()));
    }
  });

  it('get primitive, unsupported key type', async function() {
    const manager = new AesGcmKeyManager();
    const key = new PbAesCtrKey();

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyType());
    }
  });

  it('get primitive, bad version', async function() {
    const version = 1;
    const manager = new AesGcmKeyManager();
    const key = createTestKey().setVersion(version);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.versionOutOfBounds());
    }
  });

  it('get primitive, unsupported key sizes', async function() {
    const manager = new AesGcmKeyManager();

    for (let keySize = 0; keySize < 40; keySize++) {
      if (keySize === 16 || keySize === 32) {
        // Keys of sizes 16 and 32 bytes are supported.
        continue;
      }

      const key: PbAesGcmKey = createTestKey(keySize);
      try {
        await manager.getPrimitive(PRIMITIVE, key);
        fail('An exception should be thrown');
      } catch (e: any) {
        expect(e.toString()).toBe(ExceptionText.unsupportedKeySize(keySize));
      }
    }
  });

  it('get primitive, bad serialization', async function() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData().setValue(new Uint8Array([0]));

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown');
    } catch (e: any) {
      let message = e.toString();
      if (message === ExceptionText.unsupportedKeySize(0)) {
        message = ExceptionText.invalidSerializedKey();
      }
      expect(message).toBe(ExceptionText.invalidSerializedKey());
    }
  });

  // Tests for getting primitive from valid key/keyData.
  it('get primitive, from key', async function() {
    const manager = new AesGcmKeyManager();
    const key = createTestKey();

    // Get the primitive from key manager.
    const primitive: Aead = await manager.getPrimitive(PRIMITIVE, key);

    // Test the returned primitive.
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = await primitive.encrypt(plaintext, aad);
    const decryptedCiphertext = await primitive.decrypt(ciphertext, aad);

    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('get primitive, from key data', async function() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData();

    // Get primitive.
    const primitive: Aead = await manager.getPrimitive(PRIMITIVE, keyData);

    // Test the returned primitive.
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = await primitive.encrypt(plaintext, aad);
    const decryptedCiphertext = await primitive.decrypt(ciphertext, aad);

    expect(decryptedCiphertext).toEqual(plaintext);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getVersion, getKeyType and doesSupport methods

  it('get version, should be zero', function() {
    const manager = new AesGcmKeyManager();
    expect(manager.getVersion()).toBe(0);
  });

  it('get key type, should be aes gcm key type', function() {
    const manager = new AesGcmKeyManager();
    expect(manager.getKeyType()).toBe(KEY_TYPE);
  });

  it('does support, should support aes gcm key type', function() {
    const manager = new AesGcmKeyManager();
    expect(manager.doesSupport(KEY_TYPE)).toBe(true);
  });

  it('get primitive type, should be aead', function() {
    const manager = new AesGcmKeyManager();
    expect(manager.getPrimitiveType()).toBe(PRIMITIVE);
  });
});

/////////////////////////////////////////////////////////////////////////////
// Helper functions for tests

class ExceptionText {
  static unsupportedPrimitive(): string {
    return 'SecurityException: Requested primitive type which is not supported ' +
        'by this key manager.';
  }

  static unsupportedKeySize(keySize: number): string {
    return 'InvalidArgumentsException: unsupported AES key size: ' + keySize;
  }

  static versionOutOfBounds(): string {
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  static unsupportedKeyType(opt_unsupportedKeyType?: string): string {
    const prefix = 'SecurityException: Key type';
    const suffix =
        'is not supported. This key manager supports ' + KEY_TYPE + '.';

    if (opt_unsupportedKeyType) {
      return prefix + ' ' + opt_unsupportedKeyType + ' ' + suffix;
    } else {
      return prefix + ' ' + suffix;
    }
  }

  static invalidSerializedKey(): string {
    return 'SecurityException: Could not parse the input as a serialized proto of ' +
        KEY_TYPE + ' key.';
  }

  static invalidSerializedKeyFormat() {
    return 'SecurityException: Could not parse the input as a serialized proto of ' +
        KEY_TYPE + ' key format.';
  }

  static invalidKeyFormat(): string {
    return 'SecurityException: Expected AesGcmKeyFormat-proto';
  }
}

function createTestKeyFormat(opt_keySize: number = 16): PbAesGcmKeyFormat {
  const keyFormat = new PbAesGcmKeyFormat().setKeySize(opt_keySize);
  return keyFormat;
}

function createTestKey(opt_keySize: number = 16): PbAesGcmKey {
  const key = new PbAesGcmKey().setVersion(0).setKeyValue(
      Random.randBytes(opt_keySize));

  return key;
}

function createTestKeyData(opt_keySize?: number): PbKeyData {
  const keyData = new PbKeyData()
                      .setTypeUrl(KEY_TYPE)
                      .setValue(createTestKey(opt_keySize).serializeBinary())
                      .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

  return keyData;
}
