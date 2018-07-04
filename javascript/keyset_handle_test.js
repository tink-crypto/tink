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

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  /////////////////////////////////////////////////////////////////////////////
  // tests for read method
  async testRead() {
    const keysetHandle = new KeysetHandle();
    try {
      await keysetHandle.read(null, null);
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
    const keysetHandle = new KeysetHandle();
    try {
      await keysetHandle.generateNew(null);
    } catch (e) {
      assertEquals(
          'CustomError: KeysetHandle -- generateNew: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for read method
  async testWriteEncrypted() {
    const keysetHandle = new KeysetHandle();
    try {
      await keysetHandle.writeEncrypted(null, null);
    } catch (e) {
      assertEquals(
          'CustomError: KeysetHandle -- writeEncrypted: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },
});
