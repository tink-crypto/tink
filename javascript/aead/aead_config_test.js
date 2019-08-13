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

const Aead = goog.require('tink.Aead');
const AeadConfig = goog.require('tink.aead.AeadConfig');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const AesGcmKeyManager = goog.require('tink.aead.AesGcmKeyManager');
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

testSuite({
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
    let containsAesGcmKeyType = false;

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

        case AES_GCM_KEY_TYPE: {
          containsAesGcmKeyType = true;
          assertEquals(AES_GCM_VERSION, entry.getKeyManagerVersion());
          assertEquals(AES_GCM_NEW_KEY_ALLOWED, entry.getNewKeyAllowed());
          break;
        }

          // TODO add tests that contains other key types here, whenever they
          // are available in Tink.

        default:
          fail('Contains unknown key type url' + entry.getTypeUrl() + '.');
      }
    }

    assertTrue(containsAesCtrHmacAeadKeyType);
    assertTrue(containsAesGcmKeyType);
  },


  testRegister_correspondingKeyManagersWereRegistered() {
    AeadConfig.register();

    // Test that the corresponding key managers were registered.
    const aesCtrHmacKeyManager =
        Registry.getKeyManager(AES_CTR_HMAC_AEAD_KEY_TYPE);
    assertTrue(aesCtrHmacKeyManager instanceof AesCtrHmacAeadKeyManager);

    const aesGcmKeyManager = Registry.getKeyManager(AES_GCM_KEY_TYPE);
    assertTrue(aesGcmKeyManager instanceof AesGcmKeyManager);

    // TODO add tests for other key types here, whenever they are available in
    // Tink.
  },

  async testRegister_predefinedTemplatesShouldWork() {
    AeadConfig.register();
    let templates = [
      AeadKeyTemplates.aes128Gcm(), AeadKeyTemplates.aes256Gcm(),
      AeadKeyTemplates.aes128CtrHmacSha256(),
      AeadKeyTemplates.aes256CtrHmacSha256()
    ];
    // The following function adds all templates in uncompiled tests, thus if
    // a new template is added without updating AeadConfig or AeadCatalogue
    // correctly then at least the uncompiled tests should fail.
    // But the templates are included also above as the following function does
    // not add anything to the list in compiled code.
    templates = templates.concat(getListOfTemplatesFromAeadKeyTemplatesClass());
    for (let template of templates) {
      const keyData = await Registry.newKeyData(template);
      const keysetHandle = createKeysetHandleFromKeyData(keyData);

      const aead = await keysetHandle.getPrimitive(Aead);
      const plaintext = Random.randBytes(10);
      const aad = Random.randBytes(8);
      const ciphertext = await aead.encrypt(plaintext, aad);
      const decryptedCiphertext = await aead.decrypt(ciphertext, aad);

      assertObjectEquals(plaintext, decryptedCiphertext);
    }
  },
});

// Constants used in tests.
const PRIMITIVE_NAME = 'Aead';
const CATALOGUE_NAME = 'TinkAead';
const CONFIG_NAME = 'TINK_AEAD';
// TODO update whenever new key type is available.
const NUMBER_OF_SUPPORTED_KEY_TYPES = 2;

const AES_CTR_HMAC_AEAD_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
const AES_CTR_HMAC_AEAD_VERSION = 0;
const AES_CTR_HMAC_AEAD_NEW_KEY_ALLOWED = true;

const AES_GCM_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesGcmKey';
const AES_GCM_VERSION = 0;
const AES_GCM_NEW_KEY_ALLOWED = true;

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
 * Returns all templates from AeadKeyTemplates class.
 *
 * WARNING: This function works only in uncompiled code. Once the code is
 * compiled it returns only empty set due to optimizations which are run.
 * Namely
 *   - after compilation the methods are no longer methods of AeadKeyTemplates
 *       class, and
 *   - every method which is not referenced in this file or in the code used by
 *       these tests are considered as dead code and removed.
 *
 * @return {!Array<!PbKeyTemplate>}
 */
const getListOfTemplatesFromAeadKeyTemplatesClass = function() {
  let templates = [];
  for (let propertyName of Object.getOwnPropertyNames(AeadKeyTemplates)) {
    // Only public methods (i.e. not ending with '_') without arguments (i.e.
    // function.length == 0) generate key templates.
    const property = AeadKeyTemplates[propertyName];
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
