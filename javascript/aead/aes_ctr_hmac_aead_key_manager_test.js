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

const Random = goog.require('google3.third_party.tink.javascript.subtle.random');
const {Aead} = goog.require('google3.third_party.tink.javascript.aead.internal.aead');
const {AesCtrHmacAeadKeyManager} = goog.require('google3.third_party.tink.javascript.aead.aes_ctr_hmac_aead_key_manager');
const {Mac} = goog.require('google3.third_party.tink.javascript.mac.internal.mac');
const {PbAesCtrHmacAeadKey, PbAesCtrHmacAeadKeyFormat, PbAesCtrKey, PbAesCtrKeyFormat, PbAesCtrParams, PbHashType, PbHmacKey, PbHmacKeyFormat, PbHmacParams, PbKeyData} = goog.require('google3.third_party.tink.javascript.internal.proto');

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


  let keyFormat = new PbAesCtrHmacAeadKeyFormat().setAesCtrKeyFormat(
      new PbAesCtrKeyFormat());
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


  let key =
      new PbAesCtrHmacAeadKey().setVersion(0).setAesCtrKey(new PbAesCtrKey());
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
  let keyData = new PbKeyData()
                    .setTypeUrl(KEY_TYPE)
                    .setValue(createTestKey().serializeBinary())
                    .setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

  return keyData;
};

describe('aes ctr hmac aead key manager test', function() {
  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method

  // newKey method -- key formats
  it('new key bad key format', async function() {
    const keyFormat = new PbAesCtrKeyFormat();
    const manager = new AesCtrHmacAeadKeyManager();

    try {
      manager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      expect(e.toString())
          .toBe('SecurityException: Expected AesCtrHmacAeadKeyFormat-proto');
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key bad serialized key', async function() {
    // this is not a serialized key format
    const serializedKeyFormat = new Uint8Array(4);
    const manager = new AesCtrHmacAeadKeyManager();

    try {
      manager.getKeyFactory().newKey(serializedKeyFormat);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Could not parse the given Uint8Array as a serialized' +
              ' proto of ' + KEY_TYPE);
      return;
    }
    fail('An exception should be thrown.');
  });

  // newKey method -- bad parametrs of AES CTR KEY format
  it('new key not supported aes ctr key size', async function() {
    const /** number */ keySize = 11;
    const manager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();
    keyFormat.getAesCtrKeyFormat().setKeySize(keySize);

    try {
      manager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: unsupported AES key size: ' +
              keySize);
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key iv size out of range', async function() {
    const /** Array<number> */ ivSizeOutOfRange = [10, 18];
    const manager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();

    const ivSizeOutOfRangeLength = ivSizeOutOfRange.length;
    for (let i = 0; i < ivSizeOutOfRangeLength; i++) {
      keyFormat.getAesCtrKeyFormat().getParams().setIvSize(ivSizeOutOfRange[i]);
      try {
        manager.getKeyFactory().newKey(keyFormat);
      } catch (e) {
        expect(e.toString())
            .toBe(
                'SecurityException: Invalid AES CTR HMAC key format: IV size is ' +
                'out of range: ' + ivSizeOutOfRange[i]);
        continue;
      }
      fail('An exception should be thrown.');
    }
  });

  // newKey method -- bad parametrs of HMAC KEY format
  it('new key small hmac key size', async function() {
    const /** number */ keySize = 11;
    const manager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();
    keyFormat.getHmacKeyFormat().setKeySize(keySize);

    try {
      manager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Invalid AES CTR HMAC key format: HMAC key is' +
              ' too small: ' + keySize);
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key hash type unsupported', async function() {
    const manager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();
    keyFormat.getHmacKeyFormat().getParams().setHash(PbHashType.UNKNOWN_HASH);

    try {
      manager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      expect(e.toString()).toBe('SecurityException: Unknown hash type.');
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key small tag size', async function() {
    const SMALL_TAG_SIZE = 8;
    const manager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();
    keyFormat.getHmacKeyFormat().getParams().setTagSize(SMALL_TAG_SIZE);

    try {
      manager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Invalid HMAC params: tag size ' +
              SMALL_TAG_SIZE + ' is too small.');
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key big tag size for hash type', async function() {
    const tagSizes = [
      {'hashType': PbHashType.SHA1, 'tagSize': 22},
      {'hashType': PbHashType.SHA256, 'tagSize': 34},
      {'hashType': PbHashType.SHA512, 'tagSize': 66},
    ];
    const manager = new AesCtrHmacAeadKeyManager();

    let keyFormat = createTestKeyFormat();

    const tagSizesLength = tagSizes.length;
    for (let i = 0; i < tagSizesLength; i++) {
      keyFormat.getHmacKeyFormat().getParams().setHash(tagSizes[i]['hashType']);
      keyFormat.getHmacKeyFormat().getParams().setTagSize(
          tagSizes[i]['tagSize']);
      try {
        manager.getKeyFactory().newKey(keyFormat);
      } catch (e) {
        expect(e.toString())
            .toBe(
                'SecurityException: Invalid HMAC params: tag size ' +
                tagSizes[i]['tagSize'] + ' is out of range.');
        continue;
      }
      fail('An exception should be thrown.');
    }
  });

  it('new key via format proto', async function() {
    const manager = new AesCtrHmacAeadKeyManager();

    const keyFormat = createTestKeyFormat();

    const key = /** @type {!PbAesCtrHmacAeadKey}*/ (
        manager.getKeyFactory().newKey(keyFormat));

    // testing AES CTR key
    expect(key.getAesCtrKey().getKeyValue().length)
        .toBe(keyFormat.getAesCtrKeyFormat().getKeySize());
    expect(key.getAesCtrKey().getVersion()).toBe(0);
    expect(key.getAesCtrKey().getParams().getIvSize())
        .toBe(keyFormat.getAesCtrKeyFormat().getParams().getIvSize());


    // testing HMAC key
    expect(key.getHmacKey().getKeyValue().length)
        .toBe(keyFormat.getHmacKeyFormat().getKeySize());
    expect(key.getHmacKey().getVersion()).toBe(0);
    expect(key.getHmacKey().getParams().getHash())
        .toBe(keyFormat.getHmacKeyFormat().getParams().getHash());
    expect(key.getHmacKey().getParams().getTagSize())
        .toBe(keyFormat.getHmacKeyFormat().getParams().getTagSize());
  });

  it('new key via serialized format proto', async function() {
    const manager = new AesCtrHmacAeadKeyManager();

    const keyFormat = createTestKeyFormat();
    const serializedKeyFormat = keyFormat.serializeBinary();

    const key = /** @type {!PbAesCtrHmacAeadKey} */ (
        manager.getKeyFactory().newKey(serializedKeyFormat));

    // testing AES CTR key
    expect(key.getAesCtrKey().getKeyValue().length)
        .toBe(keyFormat.getAesCtrKeyFormat().getKeySize());
    expect(key.getAesCtrKey().getVersion()).toBe(0);
    expect(key.getAesCtrKey().getParams().getIvSize())
        .toBe(keyFormat.getAesCtrKeyFormat().getParams().getIvSize());


    // testing HMAC key
    expect(key.getHmacKey().getKeyValue().length)
        .toBe(keyFormat.getHmacKeyFormat().getKeySize());
    expect(key.getHmacKey().getVersion()).toBe(0);
    expect(key.getHmacKey().getParams().getHash())
        .toBe(keyFormat.getHmacKeyFormat().getParams().getHash());
    expect(key.getHmacKey().getParams().getTagSize())
        .toBe(keyFormat.getHmacKeyFormat().getParams().getTagSize());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for NewKeyData method

  it('new key data bad serialized key', async function() {
    const serializedKeyFormats = [new Uint8Array(1), new Uint8Array(0)];
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();

    const serializedKeyFormatsLength = serializedKeyFormats.length;
    for (let i = 0; i < serializedKeyFormatsLength; i++) {
      try {
        aeadKeyManager.getKeyFactory().newKeyData(serializedKeyFormats[i]);
      } catch (e) {
        expect(e.toString())
            .toBe(
                'SecurityException: Could not parse the given Uint8Array as a ' +
                'serialized proto of ' + KEY_TYPE);
        continue;
      }
      fail(
          'An exception should be thrown for the string: ' +
          serializedKeyFormats[i]);
    }
  });

  it('new key data from valid key', async function() {
    const keyFormat = createTestKeyFormat();
    const serializedKeyFormat = keyFormat.serializeBinary();
    const manager = new AesCtrHmacAeadKeyManager();

    const keyData = manager.getKeyFactory().newKeyData(serializedKeyFormat);

    expect(keyData.getTypeUrl()).toBe(KEY_TYPE);
    expect(keyData.getKeyMaterialType())
        .toBe(PbKeyData.KeyMaterialType.SYMMETRIC);

    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());

    expect(key.getAesCtrKey().getKeyValue().length)
        .toBe(keyFormat.getAesCtrKeyFormat().getKeySize());
    expect(key.getHmacKey().getKeyValue().length)
        .toBe(keyFormat.getHmacKeyFormat().getKeySize());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method

  it('get primitive unsupported key data type', async function() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let keyData = createTestKeyData().setTypeUrl('bad type url');

    try {
      await aeadKeyManager.getPrimitive(Aead, keyData);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Key type ' + keyData.getTypeUrl() +
              ' is not supported. This key manager supports ' + KEY_TYPE + '.');
      return;
    }
    fail('An exception should be thrown');
  });

  it('get primitive unsupported key type', async function() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let key = new PbAesCtrKey();

    try {
      await aeadKeyManager.getPrimitive(Aead, key);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Given key type is not supported. ' +
              'This key manager supports ' + KEY_TYPE + '.');
      return;
    }
    fail('An exception should be thrown');
  });

  it('get primitive bad version', async function() {
    const version = 1;
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getAesCtrKey().setVersion(version);

    try {
      await aeadKeyManager.getPrimitive(Aead, key);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Version is out of bound, must be between 0 ' +
              'and ' + VERSION + '.');
      return;
    }
    fail('An exception should be thrown');
  });

  it('get primitive short aes ctr key', async function() {
    const keySize = 5;
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getAesCtrKey().setKeyValue(new Uint8Array(keySize));

    try {
      await aeadKeyManager.getPrimitive(Aead, key);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'InvalidArgumentsException: unsupported AES key size: ' +
              keySize);
      return;
    }
    fail('An exception should be thrown');
  });

  it('get primitive aes ctr key small iv size', async function() {
    const /** Array<number> */ ivSizeOutOfRange = [9, 19];
    const manager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    const ivSizeOutOfRangeLength = ivSizeOutOfRange.length;
    for (let i = 0; i < ivSizeOutOfRangeLength; i++) {
      key.getAesCtrKey().getParams().setIvSize(ivSizeOutOfRange[i]);
      try {
        await manager.getPrimitive(Aead, key);
      } catch (e) {
        expect(e.toString())
            .toBe(
                'SecurityException: Invalid AES CTR HMAC key format: IV size is ' +
                'out of range: ' + ivSizeOutOfRange[i]);
        continue;
      }
      fail('An exception should be thrown.');
    }
  });

  it('get primitive short hmac key', async function() {
    const keySize = 5;
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getHmacKey().setKeyValue(new Uint8Array(keySize));

    try {
      await aeadKeyManager.getPrimitive(Aead, key);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Invalid AES CTR HMAC key format: HMAC key is' +
              ' too small: ' + keySize);
      return;
    }
    fail('An exception should be thrown');
  });

  it('get primitive hmac key unsupported hash type', async function() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getHmacKey().getParams().setHash(PbHashType.UNKNOWN_HASH);

    try {
      await aeadKeyManager.getPrimitive(Aead, key);
    } catch (e) {
      expect(e.toString()).toBe('SecurityException: Unknown hash type.');
      return;
    }
    fail('An exception should be thrown');
  });

  it('get primitive hmac key small tag size', async function() {
    const SMALL_TAG_SIZE = 9;
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    key.getHmacKey().getParams().setTagSize(SMALL_TAG_SIZE);

    try {
      await aeadKeyManager.getPrimitive(Aead, key);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Invalid HMAC params: tag size ' +
              SMALL_TAG_SIZE + ' is too small.');
      return;
    }
    fail('An exception should be thrown');
  });

  it('get primitive hmac big tag size', async function() {
    const tagSizes = [
      {'hashType': PbHashType.SHA1, 'tagSize': 22},
      {'hashType': PbHashType.SHA256, 'tagSize': 34},
      {'hashType': PbHashType.SHA512, 'tagSize': 66},
    ];
    const manager = new AesCtrHmacAeadKeyManager();

    let /** PbAesCtrHmacAeadKey */ key = createTestKey();

    const tagSizesLength = tagSizes.length;
    for (let i = 0; i < tagSizesLength; i++) {
      key.getHmacKey().getParams().setHash(tagSizes[i]['hashType']);
      key.getHmacKey().getParams().setTagSize(tagSizes[i]['tagSize']);
      try {
        await manager.getPrimitive(Aead, key);
      } catch (e) {
        expect(e.toString())
            .toBe(
                'SecurityException: Invalid HMAC params: tag size ' +
                tagSizes[i]['tagSize'] + ' is out of range.');
        continue;
      }
      fail('An exception should be thrown.');
    }
  });

  // tests for getting primitive from valid key/keyData
  it('get primitive from key', async function() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    const key = createTestKey();
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);

    const /** Aead */ primitive = await aeadKeyManager.getPrimitive(Aead, key);
    const ciphertext = await primitive.encrypt(plaintext, aad);
    const decryptedCiphertext = await primitive.decrypt(ciphertext, aad);

    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('get primitive from key data', async function() {
    const aeadKeyManager = new AesCtrHmacAeadKeyManager();
    const keyData = createTestKeyData();
    const plaintext = Random.randBytes(8);
    const aad = Random.randBytes(8);

    const /** Aead */ primitive =
        await aeadKeyManager.getPrimitive(Aead, keyData);
    const ciphertext = await primitive.encrypt(plaintext, aad);
    const decryptedCiphertext = await primitive.decrypt(ciphertext, aad);

    expect(decryptedCiphertext).toEqual(plaintext);
  });

  it('get primitive unsupported primitive', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    const keyData = createTestKeyData();

    try {
      await manager.getPrimitive(Mac, keyData);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Requested primitive type which is not ' +
              'supported by this key manager.');
      return;
    }
    fail('An exception should be thrown.');
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getVersion, getKeyType and doesSupport methods

  it('get version should be zero', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    expect(manager.getVersion()).toBe(0);
  });

  it('get key type should be aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    expect(manager.getKeyType()).toBe(KEY_TYPE);
  });

  it('does support should support aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    expect(manager.doesSupport(KEY_TYPE)).toBe(true);
  });

  it('get primitive type should be aead', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    expect(manager.getPrimitiveType()).toBe(Aead);
  });
});
