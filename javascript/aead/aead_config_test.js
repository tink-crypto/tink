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

goog.module('tink.aead.AeadConfigTest');
goog.setTestOnly('tink.aead.AeadConfigTest');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const Registry = goog.require('tink.Registry');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  tearDown() {
    Registry.reset();
  },

  testConstants() {
    assertEquals(CATALOGUE_NAME, AeadConfig.CATALOGUE_NAME);
    assertEquals(PRIMITIVE_NAME, AeadConfig.PRIMITIVE_NAME);

    assertEquals(
        AES_CTR_HMAC_AEAD_KEY_TYPE, AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL);
    assertEquals(AES_GCM_KEY_TYPE, AeadConfig.AES_GCM_TYPE_URL);
  },

  testLatest() {
    // Generate registry configuration and check its name.
    const registryConfig = AeadConfig.latest();
    assertEquals(CONFIG_NAME, registryConfig.getConfigName());

    // Verify that it contains entries for all supported key types and nothing
    // else. Moreover check the parameters of each generated entry.
    const keyTypeEntryList = registryConfig.getEntryList();
    assertEquals(NUMBER_OF_SUPPORTED_KEY_TYPES, keyTypeEntryList.length);

    let containsAesCtrHmacAeadKeyType = false;

    for (let entry of keyTypeEntryList) {
      // Primitive name as well as Catalogue name should be the same for all
      // entries.
      assertEquals(
          PRIMITIVE_NAME.toLowerCase(), entry.getPrimitiveName().toLowerCase());
      assertEquals(CATALOGUE_NAME, entry.getCatalogueName());

      switch (entry.getTypeUrl()) {
        case AES_CTR_HMAC_AEAD_KEY_TYPE: {
          containsAesCtrHmacAeadKeyType = true;
          assertEquals(AES_CTR_HMAC_AEAD_VERSION, entry.getKeyManagerVersion());
          assertEquals(
              AES_CTR_HMAC_AEAD_NEW_KEY_ALLOWED, entry.getNewKeyAllowed());
          break;
        }

          // TODO add tests that contains other key types here, whenever they
          // are available in Tink.

        default:
          fail('Contains unknown key type url' + entry.getTypeUrl() + '.');
      }
    }

    assertTrue(containsAesCtrHmacAeadKeyType);
  },


  testRegister() {
    AeadConfig.register();

    // Test that the corresponding key managers were registered.
    const aesCtrHmacKeyManager =
        Registry.getKeyManager(AES_CTR_HMAC_AEAD_KEY_TYPE);
    assertTrue(aesCtrHmacKeyManager instanceof AesCtrHmacAeadKeyManager);

    // TODO add tests for other key types here, whenever they are available in
    // Tink.
  },
});

// Constants used in tests.
const PRIMITIVE_NAME = 'Aead';
const CATALOGUE_NAME = 'TinkAead';
const CONFIG_NAME = 'TINK_AEAD';
// TODO update whenever new key type is available.
const NUMBER_OF_SUPPORTED_KEY_TYPES = 1;

const AES_CTR_HMAC_AEAD_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
const AES_CTR_HMAC_AEAD_VERSION = 0;
const AES_CTR_HMAC_AEAD_NEW_KEY_ALLOWED = true;

const AES_GCM_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesGcmKey';
