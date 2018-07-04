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

goog.module('tink.RegistryTest');
goog.setTestOnly('tink.RegistryTest');

const Registry = goog.require('tink.Registry');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  /////////////////////////////////////////////////////////////////////////////
  // tests for addCatalogue method
  async testAddCatalogue() {
    try {
      await Registry.addCatalogue('', null);
    } catch (e) {
      assertEquals('CustomError: Not implemented yet.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getCatalogue method
  async testGetCatalogue() {
    try {
      await Registry.getCatalogue('');
    } catch (e) {
      assertEquals('CustomError: Not implemented yet.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for registerKeyManager  method
  async testRegisterKeyManager() {
    try {
      await Registry.registerKeyManager('', null);
    } catch (e) {
      assertEquals('CustomError: Not implemented yet.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getKeyManager method
  async testGetKeyManager() {
    try {
      await Registry.getKeyManager('');
    } catch (e) {
      assertEquals('CustomError: Not implemented yet.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKeyData method
  async testNewKeyData() {
    try {
      await Registry.newKeyData(null);
    } catch (e) {
      assertEquals('CustomError: Not implemented yet.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method
  async testNewKey() {
    try {
      await Registry.newKey(null, '');
    } catch (e) {
      assertEquals('CustomError: Not implemented yet.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method
  async testGetPrimitive() {
    try {
      await Registry.getPrimitive(new Uint8Array(2), '');
    } catch (e) {
      assertEquals('CustomError: Not implemented yet.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitives method
  async testGetPrimitives() {
    try {
      await Registry.getPrimitives(null);
    } catch (e) {
      assertEquals('CustomError: Not implemented yet.', e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },
});
