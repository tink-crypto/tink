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

const Aead = goog.require('tink.Aead');
const AesGcmKeyManager = goog.require('tink.aead.AesGcmKeyManager');
const Mac = goog.require('tink.Mac');
const PbAesCtrKey = goog.require('proto.google.crypto.tink.AesCtrKey');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbAesGcmKey = goog.require('proto.google.crypto.tink.AesGcmKey');
const PbAesGcmKeyFormat = goog.require('proto.google.crypto.tink.AesGcmKeyFormat');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const Random = goog.require('tink.subtle.Random');
const testSuite = goog.require('goog.testing.testSuite');

const KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesGcmKey';
const VERSION = 0;
const PRIMITIVE = Aead;

testSuite({
  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method

  // newKey method -- key formats
  testNewKey_invalidKeyFormat() {
    const keyFormat = new PbAesCtrKeyFormat();
    const manager = new AesGcmKeyManager();

    try {
      manager.getKeyFactory().newKey(keyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.invalidKeyFormat(), e.toString());
    }
  },

  testNewKey_invalidSerializedKeyFormat() {
    const keyFormat = new Uint8Array(0);
    const manager = new AesGcmKeyManager();

    try {
      manager.getKeyFactory().newKey(keyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.invalidSerializedKeyFormat(), e.toString());
    }
  },


  testNewKey_unsupportedKeySizes() {
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
        assertEquals(ExceptionText.unsupportedKeySize(keySize), e.toString());
      }
    }
  },

  testNewKey_viaFormatProto() {
    const manager = new AesGcmKeyManager();

    const keyFormat = createTestKeyFormat();

    const key =
        /** @type {!PbAesGcmKey}*/ (manager.getKeyFactory().newKey(keyFormat));

    assertEquals(keyFormat.getKeySize(), key.getKeyValue().length);
  },

  testNewKey_viaSerializedFormatProto() {
    const manager = new AesGcmKeyManager();

    const keyFormat = createTestKeyFormat();
    const serializedKeyFormat = keyFormat.serializeBinary();

    const key = /** @type {!PbAesGcmKey} */ (
        manager.getKeyFactory().newKey(serializedKeyFormat));

    assertEquals(keyFormat.getKeySize(), key.getKeyValue().length);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for NewKeyData method

  testNewKeyData_shouldWork() {
    const keyFormat = createTestKeyFormat();
    const serializedKeyFormat = keyFormat.serializeBinary();
    const manager = new AesGcmKeyManager();

    const keyData = manager.getKeyFactory().newKeyData(serializedKeyFormat);

    assertEquals(KEY_TYPE, keyData.getTypeUrl());
    assertEquals(
        PbKeyData.KeyMaterialType.SYMMETRIC, keyData.getKeyMaterialType());

    const key = PbAesGcmKey.deserializeBinary(keyData.getValue());

    assertEquals(keyFormat.getKeySize(), key.getKeyValue().length);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method

  async testGetPrimitive_unsupportedKeyDataType() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData().setTypeUrl('bad_type_url');

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown');
    } catch (e) {
      assertEquals(
          ExceptionText.unsupportedKeyType(keyData.getTypeUrl()), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeyType() {
    const manager = new AesGcmKeyManager();
    const key = new PbAesCtrKey();

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyType(), e.toString());
    }
  },

  async testGetPrimitive_badVersion() {
    const version = 1;
    const manager = new AesGcmKeyManager();
    const key = createTestKey().setVersion(version);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown');
    } catch (e) {
      assertEquals(ExceptionText.versionOutOfBounds(), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeySizes() {
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
        assertEquals(ExceptionText.unsupportedKeySize(keySize), e.toString());
      }
    }
  },

  async testGetPrimitive_badSerialization() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData().setValue(new Uint8Array([]));

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown');
    } catch (e) {
      assertEquals(ExceptionText.invalidSerializedKey(), e.toString());
    }
  },

  async testGetPrimitive_unsupportedPrimitive() {
    const manager = new AesGcmKeyManager();
    const keyData = createTestKeyData();

    try {
      await manager.getPrimitive(Mac, keyData);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedPrimitive(), e.toString());
    }
  },


  // Tests for getting primitive from valid key/keyData.
  async testGetPrimitive_fromKey() {
    const manager = new AesGcmKeyManager();
    const key = createTestKey();

    // Get the primitive from key manager.
    const /** Aead */ primitive = await manager.getPrimitive(PRIMITIVE, key);

    // Test the returned primitive.
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);
    const ciphertext = await primitive.encrypt(plaintext, aad);
    const decryptedCiphertext = await primitive.decrypt(ciphertext, aad);

    assertObjectEquals(plaintext, decryptedCiphertext);
  },

  async testGetPrimitive_fromKeyData() {
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

    assertObjectEquals(plaintext, decryptedCiphertext);
  },
  /////////////////////////////////////////////////////////////////////////////
  // tests for getVersion, getKeyType and doesSupport methods

  testGetVersion_shouldBeZero() {
    const manager = new AesGcmKeyManager();
    assertEquals(0, manager.getVersion());
  },

  testGetKeyType_shouldBeAesGcmKeyType() {
    const manager = new AesGcmKeyManager();
    assertEquals(KEY_TYPE, manager.getKeyType());
  },

  testDoesSupport_shouldSupportAesGcmKeyType() {
    const manager = new AesGcmKeyManager();
    assertTrue(manager.doesSupport(KEY_TYPE));
  },

  testGetPrimitiveType_shouldBeAead() {
    const manager = new AesGcmKeyManager();
    assertEquals(PRIMITIVE, manager.getPrimitiveType());
  },
});

/////////////////////////////////////////////////////////////////////////////
// Helper functions for tests

class ExceptionText {
  /** @return {string} */
  static unsupportedPrimitive() {
    return 'CustomError: Requested primitive type which is not supported ' +
        'by this key manager.';
  }

  /**
   * @param {number} keySize
   * @return {string}
   */
  static unsupportedKeySize(keySize) {
    return 'CustomError: unsupported AES key size: ' + keySize;
  }

  /**
   * @return {string}
   */
  static versionOutOfBounds() {
    return 'CustomError: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  /**
   * @param {string=} opt_unsupportedKeyType
   * @return {string}
   */
  static unsupportedKeyType(opt_unsupportedKeyType) {
    const prefix = 'CustomError: Key type';
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
    return 'CustomError: Could not parse the input as a serialized proto of ' +
        KEY_TYPE + ' key.';
  }

  static invalidSerializedKeyFormat() {
    return 'CustomError: Could not parse the input as a serialized proto of ' +
        KEY_TYPE + ' key format.';
  }

  /**
   * @return {string}
   */
  static invalidKeyFormat() {
    return 'CustomError: Expected AesGcmKeyFormat-proto';
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
