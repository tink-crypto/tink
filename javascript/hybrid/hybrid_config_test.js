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
const {HybridDecrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_decrypt');
const {HybridEncrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_encrypt');
const HybridKeyTemplates = goog.require('tink.hybrid.HybridKeyTemplates');
const KeysetHandle = goog.require('tink.KeysetHandle');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const {PbKeyData, PbKeyStatusType, PbKeyTemplate, PbKeyset, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('hybrid config test', function() {
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
    expect(HybridConfig.ENCRYPT_PRIMITIVE_NAME).toBe(ENCRYPT_PRIMITIVE_NAME);
    expect(HybridConfig.DECRYPT_PRIMITIVE_NAME).toBe(DECRYPT_PRIMITIVE_NAME);

    expect(HybridConfig.ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE)
        .toBe(ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE);
    expect(HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE)
        .toBe(ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE);
  });

  it('register, correct key managers were registered', function() {
    HybridConfig.register();

    // Test that the corresponding key managers were registered.
    const publicKeyManager =
        Registry.getKeyManager(ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE);
    expect(publicKeyManager instanceof EciesAeadHkdfPublicKeyManager)
        .toBe(true);

    const privateKeyManager =
        Registry.getKeyManager(ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE);
    expect(privateKeyManager instanceof EciesAeadHkdfPrivateKeyManager)
        .toBe(true);
  });

  // Check that everything was registered correctly and thus new keys may be
  // generated using the predefined key templates and then they may be used for
  // encryption and decryption.
  it('register, predefined templates should work', async function() {
    HybridConfig.register();
    let templates = [
      HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm(),
      HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128CtrHmacSha256()
    ];
    // The following function adds all templates in uncompiled tests, thus if
    // a new template is added without updating HybridConfig correctly then at
    // least the uncompiled tests should fail.
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

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });
});

// Constants used in tests.
const ENCRYPT_PRIMITIVE_NAME = 'HybridEncrypt';
const DECRYPT_PRIMITIVE_NAME = 'HybridDecrypt';
const ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
const ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey';

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
