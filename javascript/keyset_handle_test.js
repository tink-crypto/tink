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
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const testSuite = goog.require('goog.testing.testSuite');
const {createKeyset} = goog.require('tink.testUtils');

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
