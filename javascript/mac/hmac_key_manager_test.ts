/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {PbAesCtrKey, PbAesCtrKeyFormat, PbHashType, PbHmacKey, PbHmacKeyFormat, PbHmacParams, PbKeyData} from '../internal/proto';
import {bytesLength} from '../internal/proto_shims';
import * as random from '../subtle/random';
import {assertInstanceof} from '../testing/internal/test_utils';

import {HmacKeyManager} from './hmac_key_manager';
import {Mac} from './internal/mac';

const VERSION = 0;
const PRIMITIVE = Mac;

const hashTypesToTagSize = new Map([
  [PbHashType.SHA1, 20], [PbHashType.SHA256, 32], [PbHashType.SHA384, 48],
  [PbHashType.SHA512, 64]
]);

describe('HmacKeyManagerTest', () => {
  const manager = new HmacKeyManager();
  // Tests for newKey method
  it('new key, empty key format', () => {
    const keyFormat = new PbHmacKeyFormat();

    expect(() => {
      manager.getKeyFactory().newKey(keyFormat);
    })
        .toThrowError(
            SecurityException, 'Invalid HMAC key format: key size not set');
  });

  it('new key, empty key format', () => {
    const keyFormat = new PbAesCtrKeyFormat();

    expect(() => {
      manager.getKeyFactory().newKey(keyFormat);
    }).toThrowError(SecurityException, 'Expected HmacKeyFormat-proto');
  });

  it('new key, invalid serialized key format', () => {
    const keyFormat = new Uint8Array(0);

    expect(() => {
      manager.getKeyFactory().newKey(keyFormat);
    })
        .toThrowError(
            SecurityException,
            'Could not parse the input as a serialized proto of ' +
                HmacKeyManager.KEY_TYPE + ' key format.');
  });

  it('new key, unsupported key sizes', () => {
    for (let keySize = 1; keySize < 16; keySize++) {
      const keyFormat = createTestKeyFormat(keySize);
      expect(() => {
        manager.getKeyFactory().newKey(keyFormat);
      })
          .toThrowError(
              SecurityException, 'Key too short, must be at least 16 bytes.');
    }
  });

  it('new key, key format with no params set', () => {
    const keyFormat = new PbHmacKeyFormat().setKeySize(16).setVersion(VERSION);

    expect(() => {
      manager.getKeyFactory().newKey(keyFormat);
    })
        .toThrowError(
            SecurityException, 'Invalid HMAC key format: params not set');
  });

  it('new key, tag size not set', () => {
    const params = new PbHmacParams().setHash(PbHashType.SHA256);
    const keyFormat =
        new PbHmacKeyFormat().setKeySize(16).setVersion(VERSION).setParams(
            params);

    expect(() => {
      manager.getKeyFactory().newKey(keyFormat);
    }).toThrowError(SecurityException, 'Invalid HMAC params: tag size not set');
  });

  it('new key, tag size too small', () => {
    const keyFormat = createTestKeyFormat(
        /* keySize = */ 16, /* tagSize = */ 8, PbHashType.SHA256);

    expect(() => {
      manager.getKeyFactory().newKey(keyFormat);
    })
        .toThrowError(
            SecurityException, 'Invalid HMAC params: tag size 8 is too small.');
  });

  it('new key, tag size too large', () => {
    for (const hashType of hashTypesToTagSize.keys()) {
      const invalidTagSize = hashTypesToTagSize.get(hashType)! + 1;
      const keyFormat =
          createTestKeyFormat(/* keySize = */ 16, invalidTagSize, hashType);
      expect(() => {
        manager.getKeyFactory().newKey(keyFormat);
      })
          .toThrowError(
              SecurityException,
              'Invalid HMAC params: tag size ' + String(invalidTagSize) +
                  ' is too large.');
    }
  });

  it('new key, unknown hash type', () => {
    const keyFormat = createTestKeyFormat(
        /* keySize = */ 16, /* tagSize = */ 16, PbHashType.UNKNOWN_HASH);

    expect(() => {
      manager.getKeyFactory().newKey(keyFormat);
    })
        .toThrowError(
            SecurityException, 'Invalid HMAC params: unknown hash type');
  });

  it('new key, via format proto works', () => {
    const keyFormats = createTestSetOfKeyFormats();
    for (const keyFormat of keyFormats) {
      const key = manager.getKeyFactory().newKey(keyFormat);

      expect(bytesLength(key.getKeyValue())).toBe(keyFormat.getKeySize());
      expect(key.getParams()).toBe(keyFormat.getParams());
    }
  });

  it('new key, via serialized format proto works', () => {
    const keyFormats = createTestSetOfKeyFormats();
    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const key = manager.getKeyFactory().newKey(serializedKeyFormat);

      expect(bytesLength(key.getKeyValue())).toBe(keyFormat.getKeySize());
      expect(key.getParams()).toEqual(keyFormat.getParams());
    }
  });

  // Test for newKeyData method
  it('new key data, should work', () => {
    const keyFormats = createTestSetOfKeyFormats();
    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = manager.getKeyFactory().newKeyData(serializedKeyFormat);

      expect(keyData.getTypeUrl()).toBe(HmacKeyManager.KEY_TYPE);
      expect(keyData.getKeyMaterialType())
          .toBe(PbKeyData.KeyMaterialType.SYMMETRIC);

      const key = PbHmacKey.deserializeBinary(keyData.getValue());
      expect(bytesLength(key.getKeyValue())).toBe(keyFormat.getKeySize());
      expect(key.getParams()).toEqual(keyFormat.getParams());
    }
  });

  // Tests for getPrimitive method
  it('get primitive, bad type url', async () => {
    const keyData = createTestKeyData().setTypeUrl('bad_type_url');

    await expectAsync(manager.getPrimitive(PRIMITIVE, keyData))
        .toBeRejectedWithError(
            SecurityException,
            'Key type bad_type_url is not supported. This key manager ' +
                'supports ' + HmacKeyManager.KEY_TYPE + '.');

  });

  it('get primitive, unsupported key type', async () => {
    const key = new PbAesCtrKey();

    await expectAsync(manager.getPrimitive(PRIMITIVE, key))
        .toBeRejectedWithError(
            SecurityException,
            'Key type is not supported. This key manager supports ' +
                HmacKeyManager.KEY_TYPE + '.');
  });

  it('get primitive, bad version', async () => {
    const version = 1;
    const key = createTestKey().setVersion(version);

    await expectAsync(manager.getPrimitive(PRIMITIVE, key))
        .toBeRejectedWithError(
            SecurityException,
            'Version is out of bound, must be between 0 and ' +
                String(VERSION) + '.');
  });

  it('get primitive, unsupported key sizes', async () => {
    for (let keySize = 1; keySize < 16; keySize++) {
      const key: PbHmacKey = createTestKey(keySize);

      await expectAsync(manager.getPrimitive(PRIMITIVE, key))
          .toBeRejectedWithError(
              SecurityException, 'Key too short, must be at least 16 bytes.');
    }
  });

  it('get primitive, bad serialization', async () => {
    const keyData = createTestKeyData().setValue(new Uint8Array([0]));

    await expectAsync(manager.getPrimitive(PRIMITIVE, keyData))
        .toBeRejectedWithError(
            SecurityException,
            'Could not parse the input as a serialized proto of ' +
                HmacKeyManager.KEY_TYPE + ' key.');
  });

  // Tests for getting primitive from valid key/keyData.
  it('get primitive, from key', async () => {
    const keyFormats = createTestSetOfKeyFormats();
    for (const keyFormat of keyFormats) {
      const key = assertInstanceof(
          manager.getKeyFactory().newKey(keyFormat), PbHmacKey);

      // Get the primitive from key manager.
      const mac: Mac = await manager.getPrimitive(PRIMITIVE, key);

      // Test the returned primitive.
      const data = random.randBytes(10);
      const tag = await mac.computeMac(data);
      const isValid = await mac.verifyMac(tag, data);

      expect(isValid).toBe(true);
    }
  });

  it('get primitive, from key data', async () => {
    const keyFormats = createTestSetOfKeyFormats();
    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = assertInstanceof(
          manager.getKeyFactory().newKeyData(serializedKeyFormat), PbKeyData);
      // Get primitive.
      const mac: Mac = await manager.getPrimitive(PRIMITIVE, keyData);

      // Test the returned primitive.
      const data = random.randBytes(10);
      const tag = await mac.computeMac(data);
      const isValid = await mac.verifyMac(tag, data);

      expect(isValid).toBe(true);
    }
  });

  // Tests for getVersion, getKeyType and doesSupport methods
  it('get version, should be zero', () => {
    expect(manager.getVersion()).toBe(VERSION);
  });

  it('get key type, should be hmac key type', () => {
    expect(manager.getKeyType())
        .toBe('type.googleapis.com/google.crypto.tink.HmacKey');
  });

  it('does support, should support hmac key type', () => {
    expect(
        manager.doesSupport('type.googleapis.com/google.crypto.tink.HmacKey'))
        .toBe(true);
  });

  it('get primitive type, should be mac', () => {
    expect(manager.getPrimitiveType()).toBe(Mac);
  });
});

// HELPER FUNCTIONS
function createTestKeyFormat(
    keySize = 16, tagSize = 16, hashType = PbHashType.SHA256): PbHmacKeyFormat {
  const keyFormat = new PbHmacKeyFormat();
  const params = new PbHmacParams().setTagSize(tagSize).setHash(hashType);
  keyFormat.setParams(params).setKeySize(keySize).setVersion(VERSION);
  return keyFormat;
}

function createTestKey(
    keySize = 16, tagSize = 16, hashType = PbHashType.SHA256): PbHmacKey {
  const params = new PbHmacParams().setTagSize(tagSize).setHash(hashType);
  const key = new PbHmacKey()
                  .setVersion(VERSION)
                  .setKeyValue(random.randBytes(keySize))
                  .setParams(params);

  return key;
}

function createTestKeyData(keySize = 16): PbKeyData {
  const keyData = new PbKeyData()
                      .setTypeUrl(HmacKeyManager.KEY_TYPE)
                      .setValue(createTestKey(keySize).serializeBinary())
                      .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

  return keyData;
}

/**
 * Creates a set of key formats with various predefined/supported
 * parameters.
 */
function createTestSetOfKeyFormats(): PbHmacKeyFormat[] {
  const keySizes = [16, 32, 64, 128];

  const keyFormats: PbHmacKeyFormat[] = [];
  for (const keySize of keySizes) {
    for (const hashType of hashTypesToTagSize.keys()) {
      const keyFormat = createTestKeyFormat(
          keySize, hashTypesToTagSize.get(hashType), hashType);
      keyFormats.push(keyFormat);
    }
  }
  return keyFormats;
}
