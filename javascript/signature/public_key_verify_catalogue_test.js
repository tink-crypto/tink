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

goog.module('tink.signature.PublicKeyVerifyCatalogueTest');
goog.setTestOnly('tink.signature.PublicKeyVerifyCatalogueTest');

const EcdsaPublicKeyManager = goog.require('tink.signature.EcdsaPublicKeyManager');
const PublicKeyVerifyCatalogue = goog.require('tink.signature.PublicKeyVerifyCatalogue');

const testSuite = goog.require('goog.testing.testSuite');

const SUPPORTED_PRIMITIVE_NAME = 'PublicKeyVerify';

testSuite({
  testGetKeyManager_wrongPrimitive() {
    const anotherPrimitiveName = 'SOME_UNSUPPORTED_PRIMITIVE';

    const catalogue = new PublicKeyVerifyCatalogue();
    try {
      catalogue.getKeyManager(
          EcdsaPublicKeyManager.KEY_TYPE, anotherPrimitiveName,
          /* minVersion = */ 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.wrongPrimitive(anotherPrimitiveName), e.toString());
    }
  },

  testGetKeyManager_versionOutOfBounds() {
    const manager = new EcdsaPublicKeyManager();
    const version = manager.getVersion() + 1;

    const catalogue = new PublicKeyVerifyCatalogue();
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

    const catalogue = new PublicKeyVerifyCatalogue();
    try {
      catalogue.getKeyManager(keyType, SUPPORTED_PRIMITIVE_NAME, version);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownKeyType(keyType), e.toString());
    }
  },

  testGetKeyManager_ecdsaPublicKeyManager() {
    const catalogue = new PublicKeyVerifyCatalogue();
    const version = 0;

    const manager = catalogue.getKeyManager(
        EcdsaPublicKeyManager.KEY_TYPE, SUPPORTED_PRIMITIVE_NAME, version);

    assertObjectEquals(new EcdsaPublicKeyManager(), manager);
  },

  testGetKeyManager_caseInsensitivePrimitiveName() {
    const catalogue = new PublicKeyVerifyCatalogue();
    const version = 0;
    const keyType = EcdsaPublicKeyManager.KEY_TYPE;

    catalogue.getKeyManager(keyType, 'publicKeyVerify', version);
    catalogue.getKeyManager(keyType, 'PublicKeyVerify', version);
    catalogue.getKeyManager(keyType, 'publickeyverify', version);
    catalogue.getKeyManager(keyType, 'PUBLICKEYVERIFY', version);
  },
});

// Helper classes and functions
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
