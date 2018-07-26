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

goog.module('tink.KeysetHandleTest');
goog.setTestOnly('tink.KeysetHandleTest');

const KeysetHandle = goog.require('tink.KeysetHandle');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  /////////////////////////////////////////////////////////////////////////////
  // tests for constructor
  async testConstructorNullKeyset() {
    try {
      new KeysetHandle(null);
    } catch (e) {
      assertEquals(ExceptionText.nullKeysetOrNoKeys(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testConstructorKeysetWithEmptyListOfKeys() {
    const keyset = new PbKeyset();
    keyset.setKeyList([]);
    try {
      new KeysetHandle(keyset);
    } catch (e) {
      assertEquals(ExceptionText.nullKeysetOrNoKeys(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testConstructorShouldWork() {
    const keyset = createKeyset();
    new KeysetHandle(keyset);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getKeyset method

  async testGetKeyset() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    const result = keysetHandle.getKeyset();
    assertObjectEquals(keyset, result);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for read method
  async testRead() {
    try {
      await KeysetHandle.read(null, null);
    } catch (e) {
      assertEquals(
          'CustomError: KeysetHandle -- read: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for generateNew method
  async testGenerateNew() {
    try {
      await KeysetHandle.generateNew(null);
    } catch (e) {
      assertEquals(
          'CustomError: KeysetHandle -- generateNew: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for write method
  async testWrite() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    try {
      await keysetHandle.write(null, null);
    } catch (e) {
      assertEquals(
          'CustomError: KeysetHandle -- write: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },
});


// Helper classes and functions used for testing purposes.
class ExceptionText {
  /** @return {string} */
  static nullKeysetOrNoKeys() {
    return 'CustomError: Keyset should be non null ' +
        'and must contain at least one key.';
  }
}

/**
 * Function for creating keys for testing purposes.
 *
 * It generates a new key with id, output prefix type and status given
 * by optional arguments. The default values are the following:
 *     id = 0x12345678,
 *     output prefix type = TINK, and
 *     status = ENABLED.
 *
 * @param {number=} opt_keyId
 * @param {boolean=} opt_legacy
 * @param {boolean=} opt_enabled
 *
 * @return{!PbKeyset.Key}
 */
const createKey = function (opt_keyId = 0x12345678, opt_legacy=false,
    opt_enabled=true) {
  let key = new PbKeyset.Key();

  if (opt_enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }

  if (opt_legacy) {
    key.setOutputPrefixType(PbOutputPrefixType.LEGACY);
  } else {
    key.setOutputPrefixType(PbOutputPrefixType.TINK);
  }

  key.setKeyId(opt_keyId);

  const keyData = new PbKeyData();
  keyData.setTypeUrl('someTypeUrl');
  keyData.setValue(new Uint8Array(10));
  keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  key.setKeyData(keyData);

  return key;
};

/**
 * Returns a valid PbKeyset which primary has id equal to 1.
 *
 * @param {number=} opt_keysetSize
 *
 * @return {!PbKeyset}
 */
const createKeyset = function(opt_keysetSize = 20) {
  const keyset = new PbKeyset();
  for (let i = 0; i < opt_keysetSize; i++) {
    const key = createKey(i + 1, /* opt_legacy = */ (i % 2) < 1,
        /* opt_enabled = */ (i % 4) < 2);
    keyset.addKey(key);
  }

  keyset.setPrimaryKeyId(1);
  return keyset;
};
