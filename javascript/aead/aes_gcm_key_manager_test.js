// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.aead.AesGcmKeyManagerTest');
goog.setTestOnly('tink.aead.AesGcmKeyManagerTest');

const Random = goog.require('google3.third_party.tink.javascript.subtle.random');
const {Aead} = goog.require('google3.third_party.tink.javascript.aead.internal.aead');
const {AesGcmKeyManager} = goog.require('google3.third_party.tink.javascript.aead.aes_gcm_key_manager');
const {Mac} = goog.require('google3.third_party.tink.javascript.mac.internal.mac');
const {PbAesCtrKey, PbAesCtrKeyFormat, PbAesGcmKey, PbAesGcmKeyFormat, PbKeyData} = goog.require('google3.third_party.tink.javascript.internal.proto');

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
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidKeyFormat());
    }
  });

  it('new key, invalid serialized key format', function() {
    const keyFormat = new Uint8Array(0);
    const manager = new AesGcmKeyManager();

    try {
      manager.getKeyFactory().newKey(keyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
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
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.unsupportedKeySize(keySize));
      }
    }
  });

  it('new key, via format proto', function() {
    const manager = new AesGcmKeyManager();

    const keyFormat = createTestKeyFormat();

    const key =
        /** @type {!PbAesGcmKey}*/ (manager.getKeyFactory().newKey(keyFormat));

    expect(key.getKeyValue().length).toBe(keyFormat.getKeySize());
  });

  it('new key, via serialized format proto', function() {
    const manager = new AesGcmKeyManager();

    const keyFormat = createTestKeyFormat();
    const serializedKeyFormat = keyFormat.serializeBinary();

    const key = /** @type {!PbAesGcmKey} */ (
        manager.getKeyFactory().newKey(serializedKeyFormat));

    expect(key.getKeyValue().length).toBe(keyFormat.getKeySize());
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

    const key = PbAesGcmKey.deserializeBinary(keyData.getValue());

    expect(key.getKeyValue().length).toBe(keyFormat.getKeySize());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method

  it('get primitive, unsupported key data type', async function() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData().setTypeUrl('bad_type_url');

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown');
    } catch (e) {
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
    } catch (e) {
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
    } catch (e) {
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

      const /** !PbAesGcmKey */ key = createTestKey(keySize);
      try {
        await manager.getPrimitive(PRIMITIVE, key);
        fail('An exception should be thrown');
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.unsupportedKeySize(keySize));
      }
    }
  });

  it('get primitive, bad serialization', async function() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData().setValue(new Uint8Array([]));

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
    }
  });

  it('get primitive, unsupported primitive', async function() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData();

    try {
      await manager.getPrimitive(Mac, keyData);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedPrimitive());
    }
  });

  // Tests for getting primitive from valid key/keyData.
  it('get primitive, from key', async function() {
    const manager = new AesGcmKeyManager();
    const key = createTestKey();

    // Get the primitive from key manager.
    const /** Aead */ primitive = await manager.getPrimitive(PRIMITIVE, key);

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
    const /** Aead */ primitive =
        await manager.getPrimitive(PRIMITIVE, keyData);

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
  /** @return {string} */
  static unsupportedPrimitive() {
    return 'SecurityException: Requested primitive type which is not supported ' +
        'by this key manager.';
  }

  /**
   * @param {number} keySize
   * @return {string}
   */
  static unsupportedKeySize(keySize) {
    return 'InvalidArgumentsException: unsupported AES key size: ' + keySize;
  }

  /**
   * @return {string}
   */
  static versionOutOfBounds() {
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  /**
   * @param {string=} opt_unsupportedKeyType
   * @return {string}
   */
  static unsupportedKeyType(opt_unsupportedKeyType) {
    const prefix = 'SecurityException: Key type';
    const suffix =
        'is not supported. This key manager supports ' + KEY_TYPE + '.';

    if (opt_unsupportedKeyType) {
      return prefix + ' ' + opt_unsupportedKeyType + ' ' + suffix;
    } else {
      return prefix + ' ' + suffix;
    }
  }

  /**
   * @return {string}
   */
  static invalidSerializedKey() {
    return 'SecurityException: Could not parse the input as a serialized proto of ' +
        KEY_TYPE + ' key.';
  }

  static invalidSerializedKeyFormat() {
    return 'SecurityException: Could not parse the input as a serialized proto of ' +
        KEY_TYPE + ' key format.';
  }

  /**
   * @return {string}
   */
  static invalidKeyFormat() {
    return 'SecurityException: Expected AesGcmKeyFormat-proto';
  }
}


/**
 * @param {number=} opt_keySize
 *
 * @return {!PbAesGcmKeyFormat}
 */
const createTestKeyFormat = function(opt_keySize = 16) {
  const keyFormat = new PbAesGcmKeyFormat().setKeySize(opt_keySize);
  return keyFormat;
};

/**
 * @param {number=} opt_keySize
 * @return {!PbAesGcmKey}
 */
const createTestKey = function(opt_keySize = 16) {
  const key = new PbAesGcmKey().setVersion(0).setKeyValue(
      Random.randBytes(opt_keySize));

  return key;
};

/**
 * @param {number=} opt_keySize
 * @return {!PbKeyData}
 */
const createTestKeyData = function(opt_keySize) {
  const keyData = new PbKeyData()
                      .setTypeUrl(KEY_TYPE)
                      .setValue(createTestKey(opt_keySize).serializeBinary())
                      .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

  return keyData;
};
