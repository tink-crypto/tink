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

goog.module('tink.signature.SignatureConfigTest');
goog.setTestOnly('tink.signature.SignatureConfigTest');

const EcdsaPrivateKeyManager = goog.require('tink.signature.EcdsaPrivateKeyManager');
const EcdsaPublicKeyManager = goog.require('tink.signature.EcdsaPublicKeyManager');
const {KeysetHandle} = goog.require('google3.third_party.tink.javascript.internal.keyset_handle');
const {PublicKeySign} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_sign');
const {PublicKeyVerify} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_verify');
const Random = goog.require('google3.third_party.tink.javascript.subtle.random');
const Registry = goog.require('google3.third_party.tink.javascript.internal.registry');
const SignatureConfig = goog.require('tink.signature.SignatureConfig');
const SignatureKeyTemplates = goog.require('tink.signature.SignatureKeyTemplates');
const {PbKeyData, PbKeyStatusType, PbKeyTemplate, PbKeyset, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');

describe('signature config test', function() {
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
    expect(SignatureConfig.VERIFY_PRIMITIVE_NAME).toBe(VERIFY_PRIMITIVE_NAME);
    expect(SignatureConfig.SIGN_PRIMITIVE_NAME).toBe(SIGN_PRIMITIVE_NAME);

    expect(SignatureConfig.ECDSA_PUBLIC_KEY_TYPE).toBe(ECDSA_PUBLIC_KEY_TYPE);
    expect(SignatureConfig.ECDSA_PRIVATE_KEY_TYPE).toBe(ECDSA_PRIVATE_KEY_TYPE);
  });

  it('register, correct key managers were registered', function() {
    SignatureConfig.register();

    // Test that the corresponding key managers were registered.
    const publicKeyManager = Registry.getKeyManager(ECDSA_PUBLIC_KEY_TYPE);
    expect(publicKeyManager instanceof EcdsaPublicKeyManager).toBe(true);

    const privateKeyManager = Registry.getKeyManager(ECDSA_PRIVATE_KEY_TYPE);
    expect(privateKeyManager instanceof EcdsaPrivateKeyManager).toBe(true);
  });

  // Check that everything was registered correctly and thus new keys may be
  // generated using the predefined key templates and then they may be used for
  // encryption and decryption.
  it('register, predefined templates should work', async function() {
    SignatureConfig.register();
    let templates = [
      SignatureKeyTemplates.ecdsaP256(),
      SignatureKeyTemplates.ecdsaP256IeeeEncoding(),
      SignatureKeyTemplates.ecdsaP384(),
      SignatureKeyTemplates.ecdsaP384IeeeEncoding(),
      SignatureKeyTemplates.ecdsaP521(),
      SignatureKeyTemplates.ecdsaP521IeeeEncoding(),

    ];
    // The following function adds all templates in uncompiled tests, thus if
    // a new template is added without updating SignatureConfig correctly then
    // at least the uncompiled tests should fail. But the templates are included
    // also above as the following function does not add anything to the list in
    // compiled code.
    templates =
        templates.concat(getListOfTemplatesFromSignatureKeyTemplatesClass());

    for (let template of templates) {
      const privateKeyData = await Registry.newKeyData(template);
      const privateKeysetHandle = createKeysetHandleFromKeyData(privateKeyData);
      const publicKeySign =
          await privateKeysetHandle.getPrimitive(PublicKeySign);

      const publicKeyData = Registry.getPublicKeyData(
          privateKeyData.getTypeUrl(), privateKeyData.getValue_asU8());
      const publicKeysetHandle = createKeysetHandleFromKeyData(publicKeyData);
      const publicKeyVerify =
          await publicKeysetHandle.getPrimitive(PublicKeyVerify);

      const data = Random.randBytes(10);
      const signature = await publicKeySign.sign(data);
      const isValid = await publicKeyVerify.verify(signature, data);

      expect(isValid).toBe(true);
    }
  });
});

// Constants used in tests.
const VERIFY_PRIMITIVE_NAME = 'PublicKeyVerify';
const SIGN_PRIMITIVE_NAME = 'PublicKeySign';
const ECDSA_PUBLIC_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EcdsaPublicKey';
const ECDSA_PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey';

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
 * Returns all templates from SignatureKeyTemplates class.
 *
 * WARNING: This function works only in uncompiled code. Once the code is
 * compiled it returns only empty set due to optimizations which are run.
 * Namely
 *   - after compilation the methods are no longer methods of
 *     SignatureKeyTemplates class, and
 *   - every method which is not referenced in this file or in the code used by
 *       these tests are considered as dead code and removed.
 *
 * @return {!Array<!PbKeyTemplate>}
 */
const getListOfTemplatesFromSignatureKeyTemplatesClass = function() {
  let templates = [];
  for (let propertyName of Object.getOwnPropertyNames(SignatureKeyTemplates)) {
    // Only public methods (i.e. not ending with '_') without arguments (i.e.
    // function.length == 0) generate key templates.
    const property = SignatureKeyTemplates[propertyName];
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
