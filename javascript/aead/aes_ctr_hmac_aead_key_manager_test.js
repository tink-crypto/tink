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

goog.module('tink.aead.AesCtrHmacAeadKeyManagerTest');
goog.setTestOnly('tink.aead.AesCtrHmacAeadKeyManagerTest');

const Aead = goog.require('tink.Aead');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const PbAesCtrHmacAeadKey = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKey');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKey = goog.require('proto.google.crypto.tink.AesCtrKey');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbAesCtrParams = goog.require('proto.google.crypto.tink.AesCtrParams');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKey = goog.require('proto.google.crypto.tink.HmacKey');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbHmacParams = goog.require('proto.google.crypto.tink.HmacParams');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const Random = goog.require('tink.subtle.Random');
const testSuite = goog.require('goog.testing.testSuite');

const KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
const VERSION = 0;

/////////////////////////////////////////////////////////////////////////////
// Helper functions for tests

/**
 * creates new AesCtrHmacAeadKeyFormat with allowed parameters
 * @return {!PbAesCtrHmacAeadKeyFormat}
 */
const createTestKeyFormat = function() {
  const KEY_SIZE = 16;
  const IV_SIZE = 12;
  const TAG_SIZE = 16;


  let keyFormat = new PbAesCtrHmacAeadKeyFormat();

  // set AES CTR key
  keyFormat.setAesCtrKeyFormat(new PbAesCtrKeyFormat());
  keyFormat.getAesCtrKeyFormat().setKeySize(KEY_SIZE);
  keyFormat.getAesCtrKeyFormat().setParams(new PbAesCtrParams());
  keyFormat.getAesCtrKeyFormat().getParams().setIvSize(IV_SIZE);

  // set HMAC key
  keyFormat.setHmacKeyFormat(new PbHmacKeyFormat());
  keyFormat.getHmacKeyFormat().setKeySize(KEY_SIZE);
  keyFormat.getHmacKeyFormat().setParams(new PbHmacParams());
  keyFormat.getHmacKeyFormat().getParams().setHash(PbHashType.SHA1);
  keyFormat.getHmacKeyFormat().getParams().setTagSize(TAG_SIZE);

  return keyFormat;
};

/**
 * creates new AesCtrHmacAeadKey with allowed parameters
 * @return {!PbAesCtrHmacAeadKey}
 */
const createTestKey = function() {
  const KEY_SIZE = 16;
  const IV_SIZE = 12;
  const TAG_SIZE = 16;


  let key = new PbAesCtrHmacAeadKey();

  key.setVersion(0);

  // set AES CTR key
  key.setAesCtrKey(new PbAesCtrKey());
  key.getAesCtrKey().setVersion(0);
  key.getAesCtrKey().setParams(new PbAesCtrParams());
  key.getAesCtrKey().getParams().setIvSize(IV_SIZE);
  key.getAesCtrKey().setKeyValue(Random.randBytes(KEY_SIZE));

  // set HMAC key
  key.setHmacKey(new PbHmacKey());
  key.getHmacKey().setVersion(0);
  key.getHmacKey().setParams(new PbHmacParams());
  key.getHmacKey().getParams().setHash(PbHashType.SHA1);
  key.getHmacKey().getParams().setTagSize(TAG_SIZE);
  key.getHmacKey().setKeyValue(Random.randBytes(KEY_SIZE));

  return key;
};

/**
 * creates new PbKeyData with allowed parameters
 * @return {!PbKeyData}
 */
const createTestKeyData = function() {
  let keyData = new PbKeyData();

  keyData.setTypeUrl(KEY_TYPE);
  keyData.setValue(createTestKey().serializeBinary());
  keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

  return keyData;
};

testSuite({

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method

  // newKey method -- key formats
  async testNewKeyBadKeyFormat() {
    const keyFormat = new PbAesCtrKeyFormat();
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      assertEquals(
          'CustomError: Expected AesCtrHmacAeadKeyFormat-proto', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testNewKeyBadSerializedKey() {
    // this is not a serialized key format
    const /** @type{string} */ serializedKeyFormat = new Uint8Array(4);
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(
          serializedKeyFormat);
    } catch (e) {
      assertEquals(
          'CustomError: Could not parse the given Uint8Array as a serialized' +
              ' proto of ' + KEY_TYPE,
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  // newKey method -- bad parametrs of AES CTR KEY format
  async testNewKeyNotSupportedAesCtrKeySize() {
    const /** number */ keySize = 11;
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();
    keyFormat.getAesCtrKeyFormat().setKeySize(keySize);

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      assertEquals(
          'CustomError: unsupported AES key size: ' + keySize, e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testNewKeyIvSizeOutOfRange() {
    const /** Array<number> */ ivSizeOutOfRange = [10, 18];
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();

    for (let i = 0; i < ivSizeOutOfRange.length; i++) {
      keyFormat.getAesCtrKeyFormat().getParams().setIvSize(ivSizeOutOfRange[i]);
      try {
        await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
      } catch (e) {
        assertEquals(
            'CustomError: Invalid AES CTR HMAC key format: IV size is ' +
                'out of range: ' + ivSizeOutOfRange[i],
            e.toString());
        continue;
      }
      fail('An exception should be thrown.');
    }
  },


  // newKey method -- bad parametrs of HMAC KEY format
  async testNewKeySmallHmacKeySize() {
    const /** number */ keySize = 11;
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();
    keyFormat.getHmacKeyFormat().setKeySize(keySize);

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      assertEquals(
          'CustomError: Invalid AES CTR HMAC key format: HMAC key is' +
              ' too small: ' + keySize,
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testNewKeyHashTypeUnsupported() {
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();
    keyFormat.getHmacKeyFormat().getParams().setHash(PbHashType.UNKNOWN_HASH);

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      assertEquals('CustomError: Unknown hash type.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testNewKeySmallTagSize() {
    const SMALL_TAG_SIZE = 8;
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();
    keyFormat.getHmacKeyFormat().getParams().setTagSize(SMALL_TAG_SIZE);

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      assertEquals(
          'CustomError: Invalid HMAC params: tag size ' + SMALL_TAG_SIZE +
              ' is too small.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testNewKeyBigTagSizeForHashType() {
    const tagSizes = [
      {'hashType': PbHashType.SHA1, 'tagSize': 22},
      {'hashType': PbHashType.SHA256, 'tagSize': 34},
      {'hashType': PbHashType.SHA512, 'tagSize': 66},
    ];
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();

    for (let i = 0; i < tagSizes.length; i++) {
      keyFormat.getHmacKeyFormat().getParams().setHash(tagSizes[i]['hashType']);
      keyFormat.getHmacKeyFormat().getParams().setTagSize(
          tagSizes[i]['tagSize']);
      try {
        await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
      } catch (e) {
        assertEquals(
            'CustomError: Invalid HMAC params: tag size ' +
                tagSizes[i]['tagSize'] + ' is out of range.',
            e.toString());
        continue;
      }
      fail('An exception should be thrown.');
    }
  },

  async testNewKeyViaFormatProto() {
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let /** @type {!PbAesCtrHmacAeadKeyFormat} */ keyFormat = createTestKeyFormat();

    let /** @type {PbAesCtrHmacAeadKey} */ key;
    try {
      key = await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      fail('Unexpected exception: ' + e.toString());
      return;
    }

    // testing AES CTR key
    assertEquals(
        keyFormat.getAesCtrKeyFormat().getKeySize(),
        key.getAesCtrKey().getKeyValue().length);
    assertEquals(0, key.getAesCtrKey().getVersion());
    assertEquals(
        keyFormat.getAesCtrKeyFormat().getParams().getIvSize(),
        key.getAesCtrKey().getParams().getIvSize());


    // testing HMAC key
    assertEquals(
        keyFormat.getHmacKeyFormat().getKeySize(),
        key.getHmacKey().getKeyValue().length);
    assertEquals(0, key.getHmacKey().getVersion());
    assertEquals(
        keyFormat.getHmacKeyFormat().getParams().getHash(),
        key.getHmacKey().getParams().getHash());
    assertEquals(
        keyFormat.getHmacKeyFormat().getParams().getTagSize(),
        key.getHmacKey().getParams().getTagSize());
  },

  async testNewKeyViaSerializedFormatProto() {
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();

    let /** @type {PbAesCtrHmacAeadKey} */ key;
    try {
      key = await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(
          keyFormat.serializeBinary());
    } catch (e) {
      fail('Unexpected exception: ' + e.toString());
      return;
    }

    // testing AES CTR key
    assertEquals(
        keyFormat.getAesCtrKeyFormat().getKeySize(),
        key.getAesCtrKey().getKeyValue().length);
    assertEquals(0, key.getAesCtrKey().getVersion());
    assertEquals(
        keyFormat.getAesCtrKeyFormat().getParams().getIvSize(),
        key.getAesCtrKey().getParams().getIvSize());


    // testing HMAC key
    assertEquals(
        keyFormat.getHmacKeyFormat().getKeySize(),
        key.getHmacKey().getKeyValue().length);
    assertEquals(0, key.getHmacKey().getVersion());
    assertEquals(
        keyFormat.getHmacKeyFormat().getParams().getHash(),
        key.getHmacKey().getParams().getHash());
    assertEquals(
        keyFormat.getHmacKeyFormat().getParams().getTagSize(),
        key.getHmacKey().getParams().getTagSize());
  },



  /////////////////////////////////////////////////////////////////////////////
  // tests for NewKeyData method

  async testNewKeyDataBadSerializedKey() {
    const serializedKeyFormats = [new Uint8Array(1), new Uint8Array(0)];
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();

    for (let i = 0; i < serializedKeyFormats.length; i++) {
      try {
        await aeadKeyManager.getKeyFactory().newKeyData(
            serializedKeyFormats[i]);
      } catch (e) {
        assertEquals(
            'CustomError: Could not parse the given Uint8Array as a ' +
                'serialized proto of ' + KEY_TYPE,
            e.toString());
        continue;
      }
      fail(
          'An exception should be thrown for the string: ' +
          serializedKeyFormats[i]);
    }
  },

  async testNewKeyDataFromValidKey() {
    const keyFormat = createTestKeyFormat();
    const serializedKeyFormat = keyFormat.serializeBinary();
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();

    let /** PbKeyData */ keyData;
    try {
      keyData =
          await aeadKeyManager.getKeyFactory().newKeyData(serializedKeyFormat);
    } catch (e) {
      fail('Unexpected exception: ' + e.toString());
    }

    assertEquals(KEY_TYPE, keyData.getTypeUrl());
    assertEquals(
        PbKeyData.KeyMaterialType.SYMMETRIC, keyData.getKeyMaterialType());

    let /** PbAesCtrHmacAeadKey */ key;
    try {
      key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());
    } catch (e) {
      fail('Unable to parse created serialized key.');
    }
    assertEquals(
        keyFormat.getAesCtrKeyFormat().getKeySize(),
        key.getAesCtrKey().getKeyValue().length);
    assertEquals(
        keyFormat.getHmacKeyFormat().getKeySize(),
        key.getHmacKey().getKeyValue().length);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method

  async testGetPrimitiveUnsupportedKeyDataType() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbKeyData */ keyData = createTestKeyData();
    keyData.setTypeUrl('bad type url');

    try {
      await aeadKeyManager.getPrimitive(keyData);
    } catch (e) {
      assertEquals(
          'CustomError: Key type ' + keyData.getTypeUrl() +
          ' is not supported. This key manager supports ' +
          KEY_TYPE + '.', e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  async testGetPrimitiveUnsupportedKeyType() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let key = new PbAesCtrKey();

    try {
      await aeadKeyManager.getPrimitive(key);
    } catch (e) {
      assertEquals(
          'CustomError: Given key type is not supported. ' +
          'This key manager supports ' + KEY_TYPE + '.', e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  async testGetPrimitiveBadVersion() {
    const version = 1;
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getAesCtrKey().setVersion(version);

    try {
      await aeadKeyManager.getPrimitive(key);
    } catch (e) {
      assertEquals(
          'CustomError: Version is out of bound, must be between 0 ' +
              'and ' + VERSION + '.',
          e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  async testGetPrimitiveShortAesCtrKey() {
    const keySize = 5;
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getAesCtrKey().setKeyValue(new Uint8Array(keySize));

    try {
      await aeadKeyManager.getPrimitive(key);
    } catch (e) {
      assertEquals(
          'CustomError: unsupported AES key size: ' + keySize, e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  async testGetPrimitiveAesCtrKeySmallIvSize() {
    const /** Array<number> */ ivSizeOutOfRange = [9, 19];
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    for (let i = 0; i < ivSizeOutOfRange.length; i++) {
      key.getAesCtrKey().getParams().setIvSize(ivSizeOutOfRange[i]);
      try {
        await aesCtrHmacAeadKeyManager.getPrimitive(key);
      } catch (e) {
        assertEquals(
            'CustomError: Invalid AES CTR HMAC key format: IV size is ' +
                'out of range: ' + ivSizeOutOfRange[i],
            e.toString());
        continue;
      }
      fail('An exception should be thrown.');
    }
  },

  async testGetPrimitiveShortHmacKey() {
    const keySize = 5;
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getHmacKey().setKeyValue(new Uint8Array(keySize));

    try {
      await aeadKeyManager.getPrimitive(key);
    } catch (e) {
      assertEquals(
          'CustomError: Invalid AES CTR HMAC key format: HMAC key is' +
              ' too small: ' + keySize,
          e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  async testGetPrimitiveHmacKeyUnsupportedHashType() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getHmacKey().getParams().setHash(PbHashType.UNKNOWN_HASH);

    try {
      await aeadKeyManager.getPrimitive(key);
    } catch (e) {
      assertEquals('CustomError: Unknown hash type.', e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  async testGetPrimitiveHmacKeySmallTagSize() {
    const SMALL_TAG_SIZE = 9;
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getHmacKey().getParams().setTagSize(SMALL_TAG_SIZE);

    try {
      await aeadKeyManager.getPrimitive(key);
    } catch (e) {
      assertEquals(
          'CustomError: Invalid HMAC params: tag size ' + SMALL_TAG_SIZE +
              ' is too small.',
          e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  async testGetPrimitiveHmacBigTagSize() {
    const tagSizes = [
      {'hashType': PbHashType.SHA1, 'tagSize': 22},
      {'hashType': PbHashType.SHA256, 'tagSize': 34},
      {'hashType': PbHashType.SHA512, 'tagSize': 66},
    ];
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();

    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    for (let i = 0; i < tagSizes.length; i++) {
      key.getHmacKey().getParams().setHash(tagSizes[i]['hashType']);
      key.getHmacKey().getParams().setTagSize(tagSizes[i]['tagSize']);
      try {
        await aesCtrHmacAeadKeyManager.getPrimitive(key);
      } catch (e) {
        assertEquals(
            'CustomError: Invalid HMAC params: tag size ' +
                tagSizes[i]['tagSize'] + ' is out of range.',
            e.toString());
        continue;
      }
      fail('An exception should be thrown.');
    }
  },

  // tests for getting primitive from valid key/keyData
  async testGetPrimitiveFromKey() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    const key = createTestKey();
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);

    let /** Aead */ primitive;
    let /** Uint8Array */ ciphertext;
    let /** Uint8Array */ decryptedCiphertext;
    try {
      primitive = await aeadKeyManager.getPrimitive(key);
    } catch (e) {
      fail('Unexpected exception, when creating primitive: ' + e.toString());
      return;
    }
    try {
      ciphertext = await primitive.encrypt(plaintext, aad);
    } catch (e) {
      fail('Unexpected exception, when encrypting plaintext: ' + e.toString());
      return;
    }
    try {
      decryptedCiphertext = await primitive.decrypt(ciphertext, aad);
    } catch (e) {
      fail('Unexpected exception, when decrypting ciphertext: ' + e.toString());
      return;
    }

    assertObjectEquals(plaintext, decryptedCiphertext);
  },

  async testGetPrimitiveFromKeyData() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    const keyData = createTestKeyData();
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);

    let /** Aead */ primitive;
    let /** Uint8Array */ ciphertext;
    let /** Uint8Array */ decryptedCiphertext;
    try {
      primitive = await aeadKeyManager.getPrimitive(keyData);
    } catch (e) {
      fail('Unexpected exception, when creating primitive: ' + e.toString());
      return;
    }
    try {
      ciphertext = await primitive.encrypt(plaintext, aad);
    } catch (e) {
      fail('Unexpected exception, when encrypting plaintext: ' + e.toString());
      return;
    }
    try {
      decryptedCiphertext = await primitive.decrypt(ciphertext, aad);
    } catch (e) {
      fail('Unexpected exception, when decrypting ciphertext: ' + e.toString());
      return;
    }

    assertObjectEquals(plaintext, decryptedCiphertext);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getVersion, getKeyType and doesSupport methods

  async testGetVersionShouldBeZero() {
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();
    assertEquals(0, aesCtrHmacAeadKeyManager.getVersion());
  },

  async testGetKeyTypeShouldBeAesCtrHmacAeadKey() {
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();
    assertEquals(KEY_TYPE, aesCtrHmacAeadKeyManager.getKeyType());
  },

  async testDoesSupportShouldSupportAesCtrHmacAeadKey() {
    const aesCtrHmacAeadKeyManager = new AesCtrHmacAeadKeyManager();
    assertTrue(aesCtrHmacAeadKeyManager.doesSupport(KEY_TYPE));
  },
});
