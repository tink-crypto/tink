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

goog.module('tink.hybrid.HybridDecryptCatalogueTest');
goog.setTestOnly('tink.hybrid.HybridDecryptCatalogueTest');

const EciesAeadHkdfPrivateKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPrivateKeyManager');
const HybridDecryptCatalogue = goog.require('tink.hybrid.HybridDecryptCatalogue');

const testSuite = goog.require('goog.testing.testSuite');

const SUPPORTED_PRIMITIVE_NAME = 'HybridDecrypt';

testSuite({
  testGetKeyManager_wrongPrimitive() {
    const anotherPrimitiveName = 'SOME_UNSUPPORTED_PRIMITIVE';

    const catalogue = new HybridDecryptCatalogue();
    try {
      catalogue.getKeyManager(
          EciesAeadHkdfPrivateKeyManager.KEY_TYPE, anotherPrimitiveName,
          /* minVersion = */ 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.wrongPrimitive(anotherPrimitiveName), e.toString());
    }
  },

  testGetKeyManager_versionOutOfBounds() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const version = manager.getVersion() + 1;

    const catalogue = new HybridDecryptCatalogue();
    try {
      catalogue.getKeyManager(
          manager.getKeyType(), SUPPORTED_PRIMITIVE_NAME, version);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.versionOutOfBounds(manager.getVersion()), e.toString());
    }
  },

  testGetKeyManager_unknownKeyType() {
    const keyType = 'UNKNOWN_KEY_TYPE';
    const version = 0;

    const catalogue = new HybridDecryptCatalogue();
    try {
      catalogue.getKeyManager(keyType, SUPPORTED_PRIMITIVE_NAME, version);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownKeyType(keyType), e.toString());
    }
  },

  testGetKeyManager_eciesAeadHkdfPrivateKeyManager() {
    const catalogue = new HybridDecryptCatalogue();
    const version = 0;

    const manager = catalogue.getKeyManager(
        EciesAeadHkdfPrivateKeyManager.KEY_TYPE, SUPPORTED_PRIMITIVE_NAME,
        version);

    assertObjectEquals(new EciesAeadHkdfPrivateKeyManager(), manager);
  },

  testGetKeyManager_caseInsensitivePrimitiveName() {
    const catalogue = new HybridDecryptCatalogue();
    const version = 0;
    const keyType = EciesAeadHkdfPrivateKeyManager.KEY_TYPE;

    catalogue.getKeyManager(keyType, 'hybridDecrypt', version);
    catalogue.getKeyManager(keyType, 'HybridDecrypt', version);
    catalogue.getKeyManager(keyType, 'hybriddecrypt', version);
    catalogue.getKeyManager(keyType, 'HYBRIDDECRYPT', version);
  },
});

class ExceptionText {
  /**
   * @param {string} requested
   * @return {string}
   */
  static wrongPrimitive(requested) {
    return 'CustomError: Requested ' + requested + ' primitive, but this ' +
        'catalogue provides key managers for ' + SUPPORTED_PRIMITIVE_NAME +
        ' primitives.';
  }

  /**
   * @param {number} availableVersion
   * @return {string}
   */
  static versionOutOfBounds(availableVersion) {
    return 'CustomError: Requested manager with higher version ' +
        'than is available. The available manager has version ' +
        availableVersion + '.';
  }

  /**
   * @param {string} keyType
   * @return {string}
   */
  static unknownKeyType(keyType) {
    return 'CustomError: There is no key manager for key type ' + keyType +
        ' available.';
  }
}
