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

const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');

const PbAesCtrHmacAeadKey = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKey');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbAesCtrParams = goog.require('proto.google.crypto.tink.AesCtrParams');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbHmacParams = goog.require('proto.google.crypto.tink.HmacParams');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');

const testSuite = goog.require('goog.testing.testSuite');

const KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';

/////////////////////////////////////////////////////////////////////////////
// Helper functions for tests

/**
 * creates new AesCtrHmacAeadKeyFormat with allowed parameters
 * @return {!PbAesCtrHmacAeadKeyFormat}
 */
const createKeyFormat = function() {
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


testSuite({

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method

  // newKey method -- key formats
  async testBadKeyFormat() {
    const keyFormat = new PbAesCtrKeyFormat();
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      assertEquals(
          'CustomError: Expected AesCtrHmacAeadKeyFormat-proto', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testBadSerializedKey() {
    const /** @type{string} */ serializedKeyFormat =
        'This is bad serialized key proto';
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(
          serializedKeyFormat);
    } catch (e) {
      assertEquals(
          'CustomError: Could not parse the given string as a serialized' +
              ' proto of ' + KEY_TYPE,
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  // newKey method -- bad parametrs of AES CTR KEY format
  async testNotSupportedAesCtrKeySize() {
    const /** number */ keySize = 11;
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    let keyFormat = createKeyFormat();
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

  async testIvSizeOutOfRange() {
    const /** Array<number> */ ivSizeOutOfRange = [10, 18];
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    let keyFormat = createKeyFormat();

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
  async testSmallHmacKeySize() {
    const /** number */ keySize = 11;
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    let keyFormat = createKeyFormat();
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

  async testHashTypeUnsupported() {
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    let keyFormat = createKeyFormat();
    keyFormat.getHmacKeyFormat().getParams().setHash(PbHashType.UNKNOWN_HASH);

    try {
      await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(keyFormat);
    } catch (e) {
      assertEquals('CustomError: Unknown hash type.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testSmallTagSize() {
    const SMALL_TAG_SIZE = 8;
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    let keyFormat = createKeyFormat();
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
  async testBigTagSizeForHashType() {
    const tagSizes = [
      {'hashType': PbHashType.SHA1, 'tagSize': 22},
      {'hashType': PbHashType.SHA256, 'tagSize': 34},
      {'hashType': PbHashType.SHA512, 'tagSize': 66},
    ];
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    let keyFormat = createKeyFormat();

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
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    let /** @type {!PbAesCtrHmacAeadKeyFormat} */ keyFormat = createKeyFormat();

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
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    let keyFormat = createKeyFormat();

    let /** @type {PbAesCtrHmacAeadKey} */ key;
    try {
      key = await aesCtrHmacAeadKeyManager.getKeyFactory().newKey(
          keyFormat.serialize());
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
  // tests for newKeyData method

  async testNewKeyData() {
    const aeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();

    try {
      await aeadKeyManager.getKeyFactory().newKeyData('some string');
    } catch (e) {
      assertEquals('CustomError: Not implemented yet', e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method

  async testGetPrimitive() {
    const aeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();
    const keyData = new PbKeyData();

    try {
      await aeadKeyManager.getPrimitive(keyData);
    } catch (e) {
      assertEquals('CustomError: Not implemented yet', e.toString());
      return;
    }
    fail('An exception should be thrown');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getVersion, getKeyType and doesSupport methods

  async testVersionShouldBeZero() {
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();
    assertEquals(0, aesCtrHmacAeadKeyManager.getVersion());
  },

  async testKeyTypeShouldBeAesCtrHmacAeadKey() {
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();
    assertEquals(KEY_TYPE, aesCtrHmacAeadKeyManager.getKeyType());
  },

  async testShouldSupportAesCtrHmacAeadKey() {
    const aesCtrHmacAeadKeyManager =
        new AesCtrHmacAeadKeyManager.AesCtrHmacAeadKeyManager();
    assertTrue(aesCtrHmacAeadKeyManager.doesSupport(KEY_TYPE));
  },
});
