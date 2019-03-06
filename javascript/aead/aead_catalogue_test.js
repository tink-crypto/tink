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

goog.module('tink.aead.AeadCatalogueTest');
goog.setTestOnly('tink.aead.AeadCatalogueTest');

const AeadCatalogue = goog.require('tink.aead.AeadCatalogue');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const AesGcmKeyManager = goog.require('tink.aead.AesGcmKeyManager');

const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');

const SUPPORTED_PRIMITIVE_NAME = 'Aead';

testSuite({
  setUp() {
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  testGetKeyManager_wrongPrimitive() {
    const anotherPrimitiveName = 'Mac';

    const catalogue = new AeadCatalogue();
    try {
      catalogue.getKeyManager(
          AesCtrHmacAeadKeyManager.KEY_TYPE, anotherPrimitiveName,
          /* minVersion = */ 0);
    } catch (e) {
      assertEquals(
          ExceptionText.wrongPrimitive(
              anotherPrimitiveName, SUPPORTED_PRIMITIVE_NAME),
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  testGetKeyManager_badVersion() {
    const manager = new AesCtrHmacAeadKeyManager();
    const version = manager.getVersion() + 1;

    const catalogue = new AeadCatalogue();
    try {
      catalogue.getKeyManager(
          manager.getKeyType(), SUPPORTED_PRIMITIVE_NAME, version);
    } catch (e) {
      assertEquals(
          ExceptionText.badVersion(manager.getVersion()), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  testGetKeyManager_unknownKeyType() {
    const keyType = 'unknown key type';
    const version = 0;

    const catalogue = new AeadCatalogue();
    try {
      catalogue.getKeyManager(keyType, SUPPORTED_PRIMITIVE_NAME, version);
    } catch (e) {
      assertEquals(ExceptionText.unknownKeyType(keyType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  testGetKeyManager_aesCtrHmacAeadKeyManager() {
    const catalogue = new AeadCatalogue();
    const version = 0;

    const manager = catalogue.getKeyManager(
        AesCtrHmacAeadKeyManager.KEY_TYPE, SUPPORTED_PRIMITIVE_NAME, version);

    assertObjectEquals(new AesCtrHmacAeadKeyManager(), manager);
  },

  testGetKeyManager_aesGcmKeyManager() {
    const catalogue = new AeadCatalogue();
    const version = 0;

    const manager = catalogue.getKeyManager(
        AesGcmKeyManager.KEY_TYPE, SUPPORTED_PRIMITIVE_NAME, version);

    assertObjectEquals(new AesGcmKeyManager(), manager);
  },

  testGetKeyManager_caseInsensitivePrimitiveName() {
    const catalogue = new AeadCatalogue();
    const version = 0;
    const keyType = AesCtrHmacAeadKeyManager.KEY_TYPE;

    catalogue.getKeyManager(keyType, 'Aead', version);
    catalogue.getKeyManager(keyType, 'aead', version);
    catalogue.getKeyManager(keyType, 'AEAD', version);
  },
});

// Helper classes and functions
class ExceptionText {
  /**
   * @param {string} requested
   * @param {string} supported
   *
   * @return {string}
   */
  static wrongPrimitive(requested, supported) {
    return 'CustomError: Requested ' + requested + ' primitive, but this ' +
        'catalogue provides key managers for ' + supported + ' primitives.';
  }

  /**
   * @param {number} availableVersion
   * @return {string}
   */
  static badVersion(availableVersion) {
    return 'CustomError: Requested manager with higher version ' +
        'than is available. The available manager has version ' +
        availableVersion + '.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static unknownKeyType(keyType) {
    return 'CustomError: There is no key manager for key type: ' + keyType +
        '.';
  }
}
