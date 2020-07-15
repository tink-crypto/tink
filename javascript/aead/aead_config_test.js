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

const {AeadConfig} = goog.require('google3.third_party.tink.javascript.aead.aead_config');
const {AeadKeyTemplates} = goog.require('google3.third_party.tink.javascript.aead.aead_key_templates');
const {Aead} = goog.require('google3.third_party.tink.javascript.aead.internal.aead');
const {AesCtrHmacAeadKeyManager} = goog.require('google3.third_party.tink.javascript.aead.aes_ctr_hmac_aead_key_manager');
const {AesGcmKeyManager} = goog.require('google3.third_party.tink.javascript.aead.aes_gcm_key_manager');
const {KeysetHandle} = goog.require('google3.third_party.tink.javascript.internal.keyset_handle');
const Random = goog.require('google3.third_party.tink.javascript.subtle.random');
const Registry = goog.require('google3.third_party.tink.javascript.internal.registry');
const {PbKeyData, PbKeyStatusType, PbKeyTemplate, PbKeyset, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('aead config test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    Registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('constants', function() {
    expect(AeadConfig.PRIMITIVE_NAME).toBe(PRIMITIVE_NAME);

    expect(AeadConfig.AES_CTR_HMAC_AEAD_TYPE_URL)
        .toBe(AES_CTR_HMAC_AEAD_KEY_TYPE);
    expect(AeadConfig.AES_GCM_TYPE_URL).toBe(AES_GCM_KEY_TYPE);
  });

  it('register, corresponding key managers were registered', function() {
    AeadConfig.register();

    // Test that the corresponding key managers were registered.
    const aesCtrHmacKeyManager =
        Registry.getKeyManager(AES_CTR_HMAC_AEAD_KEY_TYPE);
    expect(aesCtrHmacKeyManager instanceof AesCtrHmacAeadKeyManager).toBe(true);

    const aesGcmKeyManager = Registry.getKeyManager(AES_GCM_KEY_TYPE);
    expect(aesGcmKeyManager instanceof AesGcmKeyManager).toBe(true);

    // TODO add tests for other key types here, whenever they are available in
    // Tink.
  });

  it('register, predefined templates should work', async function() {
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

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });
});

// Constants used in tests.
const PRIMITIVE_NAME = 'Aead';
const AES_CTR_HMAC_AEAD_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey';
const AES_GCM_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.AesGcmKey';

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
