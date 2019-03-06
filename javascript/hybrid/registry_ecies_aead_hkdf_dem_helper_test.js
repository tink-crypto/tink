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

goog.module('tink.hybrid.RegistryEciesAeadHkdfDemHelperTest');
goog.setTestOnly('tink.hybrid.RegistryEciesAeadHkdfDemHelperTest');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const RegistryEciesAeadHkdfDemHelper = goog.require('tink.hybrid.RegistryEciesAeadHkdfDemHelper');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  setUp() {
    AeadConfig.register();
  },

  tearDown() {
    Registry.reset();
  },

  //////////////////////////////////////////////////////////////////////////////
  // Tests for constructor
  //////////////////////////////////////////////////////////////////////////////

  testConstructor_unsupportedKeyType() {
    const template = AeadKeyTemplates.aes128CtrHmacSha256();
    template.setTypeUrl('some_unsupported_type_url');

    try {
      new RegistryEciesAeadHkdfDemHelper(template);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.unsupportedTypeUrl(template.getTypeUrl()),
          e.toString());
    }
  },

  testConstructor_invalidKeyFormats() {
    // Some valid AES-GCM and AES-CTR-HMAC key templates.
    const templates =
        [AeadKeyTemplates.aes128CtrHmacSha256(), AeadKeyTemplates.aes128Gcm()];
    const invalidKeyFormats = [new Uint8Array(0), new Uint8Array([0, 1, 2])];

    // Test that if the value is changed to invalid key format than the DEM
    // helper throws an exception.
    for (let template of templates) {
      for (let invalidKeyFormat of invalidKeyFormats) {
        template.setValue(invalidKeyFormat);

        try {
          new RegistryEciesAeadHkdfDemHelper(template);
          fail('An exception should be thrown.');
        } catch (e) {
          assertEquals(
              ExceptionText.invalidKeyFormat(template.getTypeUrl()),
              e.toString());
        }
      }
    }
  },

  testConstructor_aes128CtrHmacSha256KeyTemplate() {
    const template = AeadKeyTemplates.aes128CtrHmacSha256();
    const helper = new RegistryEciesAeadHkdfDemHelper(template);

    // Expected size is a sum of AES CTR key length and HMAC key length.
    const expectedSize = 16 + 32;
    assertEquals(expectedSize, helper.getDemKeySizeInBytes());
  },

  testConstructor_aes256CtrHmacSha256KeyTemplate() {
    const template = AeadKeyTemplates.aes256CtrHmacSha256();
    const helper = new RegistryEciesAeadHkdfDemHelper(template);

    // Expected size is a sum of AES CTR key length and HMAC key length.
    const expectedSize = 32 + 32;
    assertEquals(expectedSize, helper.getDemKeySizeInBytes());
  },

  testConstructor_aes128Gcm() {
    const template = AeadKeyTemplates.aes128Gcm();
    const helper = new RegistryEciesAeadHkdfDemHelper(template);

    // Expected size is equal to the size of key.
    const expectedSize = 16;
    assertEquals(expectedSize, helper.getDemKeySizeInBytes());
  },

  testConstructor_aes256Gcm() {
    const template = AeadKeyTemplates.aes256Gcm();
    const helper = new RegistryEciesAeadHkdfDemHelper(template);

    // Expected size is equal to the size of key.
    const expectedSize = 32;
    assertEquals(expectedSize, helper.getDemKeySizeInBytes());
  },

  //////////////////////////////////////////////////////////////////////////////
  // Tests for getAead method
  //////////////////////////////////////////////////////////////////////////////

  async testGetAead_invalidKeyLength() {
    const template = AeadKeyTemplates.aes128CtrHmacSha256();
    // Expected size is a sum of AES CTR key length and HMAC key length.
    const expectedKeyLength = 16 + 32;
    const helper = new RegistryEciesAeadHkdfDemHelper(template);
    const keyLength = 2;

    try {
      await helper.getAead(new Uint8Array(keyLength));
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.invalidKeyLength(expectedKeyLength, keyLength),
          e.toString());
    }
  },

  async testGetAead_differentTemplates() {
    const templates = [
      AeadKeyTemplates.aes128CtrHmacSha256(), AeadKeyTemplates.aes128Gcm(),
      AeadKeyTemplates.aes256CtrHmacSha256(), AeadKeyTemplates.aes256Gcm()
    ];

    for (let template of templates) {
      const helper = new RegistryEciesAeadHkdfDemHelper(template);
      // Compute some demKey of size corresponding to the template.
      // The result of getDemKeySizeInBytes is the expected one for the given
      // templates as it was tested for these templates in previous tests.
      const demKey = Random.randBytes(helper.getDemKeySizeInBytes());

      // Get Aead from helper.
      const aead = await helper.getAead(demKey);
      assertTrue(aead != null);

      // Test the Aead instance.
      const plaintext = Random.randBytes(10);
      const aad = Random.randBytes(10);
      const ciphertext = await aead.encrypt(plaintext, aad);
      const decryptedCiphertext = await aead.decrypt(ciphertext, aad);

      assertObjectEquals(plaintext, decryptedCiphertext);
    }
  },
});

// Helper classes and functions
class ExceptionText {
  /**
   * @param {string} typeUrl
   * @return {string}
   */
  static unsupportedTypeUrl(typeUrl) {
    return 'CustomError: Key type URL ' + typeUrl + ' is not supported.';
  }

  /**
   * @param {string} keyType
   * @return {string}
   */
  static invalidKeyFormat(keyType) {
    return 'CustomError: Could not parse the given Uint8Array as ' +
        'a serialized proto of ' + keyType + '.';
  }

  /**
   * @param {number} expectedKeyLength
   * @param {number} actualKeyLength
   * @return {string}
   */
  static invalidKeyLength(expectedKeyLength, actualKeyLength) {
    return 'CustomError: Key is not of the correct length, expected length: ' +
        expectedKeyLength + ', but got key of length: ' + actualKeyLength + '.';
  }
}
