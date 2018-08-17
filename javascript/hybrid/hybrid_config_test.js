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

goog.module('tink.hybrid.HybridConfigTest');
goog.setTestOnly('tink.hybrid.HybridConfigTest');

const EciesAeadHkdfPrivateKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPrivateKeyManager');
const EciesAeadHkdfPublicKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPublicKeyManager');
const HybridConfig = goog.require('tink.hybrid.HybridConfig');
const Registry = goog.require('tink.Registry');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  tearDown() {
    Registry.reset();
  },

  testConstants() {
    assertEquals(ENCRYPT_CATALOGUE_NAME, HybridConfig.ENCRYPT_CATALOGUE_NAME);
    assertEquals(ENCRYPT_PRIMITIVE_NAME, HybridConfig.ENCRYPT_PRIMITIVE_NAME);
    assertEquals(DECRYPT_CATALOGUE_NAME, HybridConfig.DECRYPT_CATALOGUE_NAME);
    assertEquals(DECRYPT_PRIMITIVE_NAME, HybridConfig.DECRYPT_PRIMITIVE_NAME);

    assertEquals(
        ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE,
        HybridConfig.ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE);
    assertEquals(
        ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE,
        HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE);
  },

  testLatest() {
    // Generate registry configuration and check its name.
    const registryConfig = HybridConfig.latest();
    assertEquals(CONFIG_NAME, registryConfig.getConfigName());

    // Verify that it contains entries for all supported key types and nothing
    // else. Moreover check the parameters of each generated entry.
    const keyTypeEntryList = registryConfig.getEntryList();
    assertEquals(NUMBER_OF_SUPPORTED_KEY_TYPES, keyTypeEntryList.length);

    let containsEciesAeadHkdfPublicKeyType = false;
    let containsEciesAeadHkdfPrivateKeyType = false;

    for (let entry of keyTypeEntryList) {
      const typeUrl = entry.getTypeUrl();
      switch (typeUrl) {
        case ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE: {
          containsEciesAeadHkdfPrivateKeyType = true;
          assertEquals(DECRYPT_PRIMITIVE_NAME, entry.getPrimitiveName());
          assertEquals(DECRYPT_CATALOGUE_NAME, entry.getCatalogueName());
          assertEquals(
              ECIES_AEAD_HKDF_PRIVATE_KEY_MANAGER_VERSION,
              entry.getKeyManagerVersion());
          assertEquals(true, entry.getNewKeyAllowed());
          break;
        }

        case ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE: {
          containsEciesAeadHkdfPublicKeyType = true;
          assertEquals(ENCRYPT_PRIMITIVE_NAME, entry.getPrimitiveName());
          assertEquals(ENCRYPT_CATALOGUE_NAME, entry.getCatalogueName());
          assertEquals(
              ECIES_AEAD_HKDF_PUBLIC_KEY_MANAGER_VERSION,
              entry.getKeyManagerVersion());
          assertEquals(true, entry.getNewKeyAllowed());
          break;
        }

        default: {
          assertObjectEquals(null, entry);
          fail('Contains unknown key type url ' + typeUrl + '.');
        }
      }
    }

    assertTrue(containsEciesAeadHkdfPublicKeyType);
    assertTrue(containsEciesAeadHkdfPrivateKeyType);
  },


  testRegister_correctKeyManagersWereRegistered() {
    HybridConfig.register();

    // Test that the corresponding key managers were registered.
    const publicKeyManager =
        Registry.getKeyManager(ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE);
    assertTrue(publicKeyManager instanceof EciesAeadHkdfPublicKeyManager);

    const privateKeyManager =
        Registry.getKeyManager(ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE);
    assertTrue(privateKeyManager instanceof EciesAeadHkdfPrivateKeyManager);
  },

  // TODO add a test that after HybridConfig.register() everything is working
  // properly when HybridTemplates are in Tink.
});

// Constants used in tests.
const ENCRYPT_PRIMITIVE_NAME = 'HybridEncrypt';
const ENCRYPT_CATALOGUE_NAME = 'TinkHybridEncrypt';
const DECRYPT_PRIMITIVE_NAME = 'HybridDecrypt';
const DECRYPT_CATALOGUE_NAME = 'TinkHybridDecrypt';
const CONFIG_NAME = 'TINK_HYBRID';
const NUMBER_OF_SUPPORTED_KEY_TYPES = 2;

const ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
const ECIES_AEAD_HKDF_PUBLIC_KEY_MANAGER_VERSION = 0;

const ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey';
const ECIES_AEAD_HKDF_PRIVATE_KEY_MANAGER_VERSION = 0;
