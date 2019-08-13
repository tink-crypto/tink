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
const HybridDecrypt = goog.require('tink.HybridDecrypt');
const HybridEncrypt = goog.require('tink.HybridEncrypt');
const HybridKeyTemplates = goog.require('tink.hybrid.HybridKeyTemplates');
const KeysetHandle = goog.require('tink.KeysetHandle');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');

testSuite({
  shouldRunTests() {
    return !userAgent.EDGE;  // b/120286783
  },

  setUp() {
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    Registry.reset();
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
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

  // Check that everything was registered correctly and thus new keys may be
  // generated using the predefined key templates and then they may be used for
  // encryption and decryption.
  async testRegister_predefinedTemplatesShouldWork() {
    HybridConfig.register();
    let templates = [
      HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm(),
      HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128CtrHmacSha256()
    ];
    // The following function adds all templates in uncompiled tests, thus if
    // a new template is added without updating HybridConfig or HybridCatalogue
    // correctly then at least the uncompiled tests should fail.
    // But the templates are included also above as the following function does
    // not add anything to the list in compiled code.
    templates =
        templates.concat(getListOfTemplatesFromHybridKeyTemplatesClass());

    for (let template of templates) {
      const privateKeyData = await Registry.newKeyData(template);
      const privateKeysetHandle = createKeysetHandleFromKeyData(privateKeyData);
      const hybridDecrypt =
          await privateKeysetHandle.getPrimitive(HybridDecrypt);

      const publicKeyData = Registry.getPublicKeyData(
          privateKeyData.getTypeUrl(), privateKeyData.getValue_asU8());
      const publicKeysetHandle = createKeysetHandleFromKeyData(publicKeyData);
      const hybridEncrypt =
          await publicKeysetHandle.getPrimitive(HybridEncrypt);

      const plaintext = new Uint8Array(Random.randBytes(10));
      const contextInfo = new Uint8Array(Random.randBytes(8));
      const ciphertext = await hybridEncrypt.encrypt(plaintext, contextInfo);
      const decryptedCiphertext =
          await hybridDecrypt.decrypt(ciphertext, contextInfo);

      assertObjectEquals(plaintext, decryptedCiphertext);
    }
  },
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

/**
 * Creates a keyset containing only the key given by keyData and returns it
 * wrapped in a KeysetHandle.
 *
 * @param {!PbKeyData} keyData
 * @return {!KeysetHandle}
 */
const createKeysetHandleFromKeyData = function(keyData) {
  const keyId = 1;
  const key = new PbKeyset.Key()
                  .setKeyData(keyData)
                  .setStatus(PbKeyStatusType.ENABLED)
                  .setKeyId(keyId)
                  .setOutputPrefixType(PbOutputPrefixType.TINK);

  const keyset = new PbKeyset();
  keyset.addKey(key);
  keyset.setPrimaryKeyId(keyId);
  return new KeysetHandle(keyset);
};

/**
 * Returns all templates from HybridKeyTemplates class.
 *
 * WARNING: This function works only in uncompiled code. Once the code is
 * compiled it returns only empty set due to optimizations which are run.
 * Namely
 *   - after compilation the methods are no longer methods of HybridKeyTemplates
 *       class, and
 *   - every method which is not referenced in this file or in the code used by
 *       these tests are considered as dead code and removed.
 *
 * @return {!Array<!PbKeyTemplate>}
 */
const getListOfTemplatesFromHybridKeyTemplatesClass = function() {
  let templates = [];
  for (let propertyName of Object.getOwnPropertyNames(HybridKeyTemplates)) {
    // Only public methods (i.e. not ending with '_') without arguments (i.e.
    // function.length == 0) generate key templates.
    const property = HybridKeyTemplates[propertyName];
    if (typeof property === 'function' && property.length === 0 &&
        propertyName[propertyName.length - 1] != '_') {
      const template = property();
      if (template instanceof PbKeyTemplate) {
        templates = templates.concat([template]);
      }
    }
  }
  return templates;
};
