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

goog.module('tink.RegistryTest');
goog.setTestOnly('tink.RegistryTest');

const Aead = goog.require('tink.Aead');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const Catalogue = goog.require('tink.Catalogue');
const EncryptThenAuthenticate = goog.require('tink.subtle.EncryptThenAuthenticate');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const Mac = goog.require('tink.Mac');
const PbAesCtrHmacAeadKey = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKey');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKey = goog.require('proto.google.crypto.tink.AesCtrKey');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbAesCtrParams = goog.require('proto.google.crypto.tink.AesCtrParams');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbHmacParams = goog.require('proto.google.crypto.tink.HmacParams');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbMessage = goog.require('jspb.Message');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const Registry = goog.require('tink.Registry');
const SecurityException = goog.require('tink.exception.SecurityException');

const testSuite = goog.require('goog.testing.testSuite');

////////////////////////////////////////////////////////////////////////////////
// tests
////////////////////////////////////////////////////////////////////////////////

testSuite({
  async tearDown() {
    Registry.reset();
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for addCatalogue method
  async testAddCatalogueNullCatalogue() {
    try {
      Registry.addCatalogue('some catalogue', null);
    } catch (e) {
      assertEquals(ExceptionText.nullCatalogue(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddCatalogueEmptyName() {
    try {
      Registry.addCatalogue('', new DummyCatalogue1());
    } catch (e) {
      assertEquals(ExceptionText.missingCatalogueName(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddCatalogueOverwritingAttempt() {
    try {
      Registry.addCatalogue('some catalogue', new DummyCatalogue1());
      Registry.addCatalogue('some catalogue', new DummyCatalogue2());
    } catch (e) {
      assertEquals(ExceptionText.overwrittingCatalogueAttempt(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddFewCatalogues() {
    for (let i = 0; i < 10; i++) {
      Registry.addCatalogue('first' + i.toString(), new DummyCatalogue1());
      Registry.addCatalogue('second' + i.toString(), new DummyCatalogue2());
      Registry.addCatalogue('third' + i.toString(), new DummyCatalogue3());
    }
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getCatalogue method
  async testGetCatalogueMissingCatalogue() {
    const name = 'first';

    try {
      Registry.getCatalogue(name);
    } catch (e) {
      assertEquals(ExceptionText.catalogueMissing(name), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetCatalogueWhichWasAdded() {
    const numberOfCatalogues = 10;
    let catalogueNames = [];

    for (let i = 0; i < numberOfCatalogues; i++) {
      catalogueNames.push('catalogue' + i.toString());
      Registry.addCatalogue(catalogueNames[i], new DummyCatalogue1());
    }

    for (let i = 0; i < numberOfCatalogues; i++) {
      const result = Registry.getCatalogue(catalogueNames[i]);
      assertTrue(result instanceof DummyCatalogue1);
    }
  },



  /////////////////////////////////////////////////////////////////////////////
  // tests for registerKeyManager  method
  async testRegisterKeyManagerEmptyManager() {
    try {
      Registry.registerKeyManager('some key type', null);
    } catch (e) {
      assertEquals(ExceptionText.nullKeyManager(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testRegisterKeyManagerUndefinedKeyType() {
    try {
      Registry.registerKeyManager('', new DummyKeyManager1('some_key_type'));
    } catch (e) {
      assertEquals(ExceptionText.undefinedKeyType(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testRegisterKeyManagerOverwritingAttempt() {
    const keyType = 'someKeyType';

    try {
      Registry.registerKeyManager(keyType, new DummyKeyManager1(keyType));
      Registry.registerKeyManager(keyType, new DummyKeyManager2(keyType));
    } catch (e) {
      assertEquals(
          ExceptionText.keyManagerOverwrittingAttempt(keyType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testRegisterKeyManagerWithWrongKeyType() {
    const keyType = 'someKeyType';
    const differentKeyType = 'differentKeyType';

    try {
      Registry.registerKeyManager(
          differentKeyType, new DummyKeyManager1(keyType));
    } catch (e) {
      assertEquals(
          ExceptionText.notSupportedKey(differentKeyType),
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testRegisterKeyManagerShouldWork() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const keyManager2 = new DummyKeyManager2('otherKeyType');

    Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1);
    Registry.registerKeyManager(keyManager2.getKeyType(), keyManager2, false);
  },

  // Testing newKeyAllowed behavior -- should hold the most restrictive setting.
  async testRegisterKeyManagerMoreRestrictiveNewKeyAllowed() {
    const keyType = 'someTypeUrl';
    const keyManager1 = new DummyKeyManager1(keyType);
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(keyType);

    //Register the key manager with new_key_allowed and test that it is possible
    //to create a new key data.
    Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1);
    await Registry.newKeyData(keyTemplate);

    //Restrict the key manager and test that new key data cannot be created.
    Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1, false);
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e) {
      assertEquals(ExceptionText.newKeyForbidden(keyType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testRegisterKeyManagerLessRestrictiveNewKeyAllowed() {
    const keyType = 'someTypeUrl';
    const keyManager1 = new DummyKeyManager1(keyType);
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(keyType);

    Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1, false);

    // Re-registering key manager with less restrictive setting should not be
    // possible and the restriction has to be still true (i.e. new key data
    // cannot be created).
    try {
      Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1);
    } catch (e) {
      assertEquals(
          ExceptionText.prohibitedChangeToLessRestricted(
              keyManager1.getKeyType()),
          e.toString());
    }
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e) {
      assertEquals(ExceptionText.newKeyForbidden(keyType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getKeyManager method
  async testGetKeyManagerShouldWork() {
    const numberOfKeyManagers = 10;
    let keyManagers1 = [];
    let keyManagers2 = [];

    for (let i = 0; i < numberOfKeyManagers; i++) {
      keyManagers1.push(new DummyKeyManager1('someKeyType' + i.toString()));
      keyManagers2.push(new DummyKeyManager2('otherKeyType' + i.toString()));

      Registry.registerKeyManager(
          keyManagers1[i].getKeyType(), keyManagers1[i]);
      Registry.registerKeyManager(
          keyManagers2[i].getKeyType(), keyManagers2[i]);
    }

    let result;
    for (let i = 0; i < numberOfKeyManagers; i++) {
      result = Registry.getKeyManager(keyManagers1[i].getKeyType());
      assertObjectEquals(keyManagers1[i], result);

      result = Registry.getKeyManager(keyManagers2[i].getKeyType());
      assertObjectEquals(keyManagers2[i], result);
    }
  },

  async testGetKeyManagerNotRegisteredKeyType() {
    const keyType = 'some_key_type';

    try {
      Registry.getKeyManager(keyType);
    } catch (e) {
      assertEquals(
          ExceptionText.notRegisteredKeyType(keyType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKeyData method
  async testNewKeyDataNoManagerForGivenKeyType() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const differentKeyType = 'otherKeyType';
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(differentKeyType);

    Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1);
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e) {
      assertEquals(
          ExceptionText.notRegisteredKeyType(differentKeyType),
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testNewKeyDataNewKeyDisallowed() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(keyManager1.getKeyType());

    Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1, false);
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e) {
      assertEquals(
          ExceptionText.newKeyForbidden(keyManager1.getKeyType()),
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testNewKeyDataNewKeyAllowed() {
    const /** Array<string> */ keyTypes = [];
    for (let i = 0; i < 10; i++) {
      keyTypes.push('someKeyType' + i.toString());
    }

    const keyTypesLength = keyTypes.length;
    for (let i = 0; i < keyTypesLength; i++) {
      Registry.registerKeyManager(
          keyTypes[i], new DummyKeyManager1(keyTypes[i]), true);
    }

    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate();
      keyTemplate.setTypeUrl(keyTypes[i]);
      const result = await Registry.newKeyData(keyTemplate);
      assertEquals(keyTypes[i], result.getTypeUrl());
    }
  },

  async testNewKeyDataNewKeyIsAllowedAutomatically() {
    const /** Array<string> */ keyTypes = [];
    for (let i = 0; i < 10; i++) {
      keyTypes.push('someKeyType' + i.toString());
    }

    const keyTypesLength = keyTypes.length;
    for (let i = 0; i < keyTypesLength; i++) {
      Registry.registerKeyManager(
          keyTypes[i], new DummyKeyManager1(keyTypes[i]));
    }

    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate();
      keyTemplate.setTypeUrl(keyTypes[i]);
      const result = await Registry.newKeyData(keyTemplate);
      assertEquals(keyTypes[i], result.getTypeUrl());
    }
  },

  async testNewKeyDataWithAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager.getKeyType(), manager);
    const keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);

    // Checks that correct AES CTR HMAC AEAD key was returned.
    const keyFormat =
        PbAesCtrHmacAeadKeyFormat.deserializeBinary(keyTemplate.getValue());
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());
    // Check AES CTR key.
    assertEquals(
        key.getAesCtrKey().getKeyValue().length,
        keyFormat.getAesCtrKeyFormat().getKeySize());
    assertObjectEquals(
        key.getAesCtrKey().getParams(),
        keyFormat.getAesCtrKeyFormat().getParams());
    // Check HMAC key.
    assertEquals(
        key.getHmacKey().getKeyValue().length,
        keyFormat.getHmacKeyFormat().getKeySize());
    assertObjectEquals(
        key.getHmacKey().getParams(), keyFormat.getHmacKeyFormat().getParams());
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method
  async testNewKey_noManagerForGivenKeyType() {
    const notRegisteredKeyType = 'not_registered_key_type';
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(notRegisteredKeyType);

    try {
      await Registry.newKey(keyTemplate);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.notRegisteredKeyType(notRegisteredKeyType),
          e.toString());
    }
  },

  async testNewKey_newKeyDisallowed() {
    const keyManager = new DummyKeyManagerForNewKeyTests('someKeyType');
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(keyManager.getKeyType());
    Registry.registerKeyManager(
        keyManager.getKeyType(), keyManager, /* opt_newKeyAllowed = */ false);

    try {
      await Registry.newKey(keyTemplate);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.newKeyForbidden(keyManager.getKeyType()), e.toString());
    }
  },

  async testNewKey_shouldWork() {
    const /** Array<string> */ keyTypes = [];
    const /** Array<Uint8Array> */ newKeyMethodResult = [];
    const keyTypesLength = 10;

    // Add some keys to Registry.
    for (let i = 0; i < keyTypesLength; i++) {
      keyTypes.push('someKeyType' + i.toString());
      newKeyMethodResult.push(new Uint8Array([i + 1]));

      Registry.registerKeyManager(
          keyTypes[i],
          new DummyKeyManagerForNewKeyTests(keyTypes[i], newKeyMethodResult[i]),
          /* newKeyAllowed = */ true);
    }

    // For every keyType verify that it calls new key method of the
    // corresponding KeyManager (KeyFactory).
    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate();
      keyTemplate.setTypeUrl(keyTypes[i]);

      const key =
          /** @type {!PbAesCtrKey} */ (await Registry.newKey(keyTemplate));

      // The new key method of DummyKeyFactory returns an AesCtrKey which
      // KeyValue is set to corresponding value in newKeyMethodResult.
      assertEquals(newKeyMethodResult[i], key.getKeyValue());
    }
  },

  async testNewKey_withAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager.getKeyType(), manager);
    const keyTemplate = AeadKeyTemplates.aes256CtrHmacSha256();

    const key =
        /** @type{!PbAesCtrHmacAeadKey} */ (await Registry.newKey(keyTemplate));

    // Checks that correct AES CTR HMAC AEAD key was returned.
    const keyFormat =
        PbAesCtrHmacAeadKeyFormat.deserializeBinary(keyTemplate.getValue());
    // Check AES CTR key.
    assertEquals(
        key.getAesCtrKey().getKeyValue().length,
        keyFormat.getAesCtrKeyFormat().getKeySize());
    assertObjectEquals(
        key.getAesCtrKey().getParams(),
        keyFormat.getAesCtrKeyFormat().getParams());
    // Check HMAC key.
    assertEquals(
        key.getHmacKey().getKeyValue().length,
        keyFormat.getHmacKeyFormat().getKeySize());
    assertObjectEquals(
        key.getHmacKey().getParams(), keyFormat.getHmacKeyFormat().getParams());
  },


  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method
  async testGetPrimitiveDifferentKeyTypes() {
    const keyDataType = 'key_data_key_type_url';
    const anotherType = 'another_key_type_url';
    const keyData = new PbKeyData();
    keyData.setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(null, keyData, anotherType);
    } catch (e) {
      assertEquals(
          ExceptionText.keyTypesAreNotMatching(keyDataType, anotherType),
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetPrimitiveWithoutDefiningKeyType() {
    // Get primitive from key proto without key type.
    try {
      await Registry.getPrimitive(null, new PbMessage);
    } catch (e) {
      assertEquals(ExceptionText.keyTypeNotDefined(), e.toString());
    }
  },

  async testGetPrimitiveMissingKeyManager() {
    const keyDataType = 'key_data_key_type_url';
    const keyData = new PbKeyData();
    keyData.setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(null, keyData);
    } catch (e) {
      assertEquals(
          ExceptionText.notRegisteredKeyType(keyDataType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetPrimitiveFromAesCtrHmacAeadKeyData() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager.getKeyType(), manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);

    const primitive =
        await Registry.getPrimitive(manager.getPrimitiveType(), keyData);
    assertTrue(primitive instanceof EncryptThenAuthenticate);
  },

  async testGetPrimitiveFromAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager.getKeyType(), manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());

    const primitive = await Registry.getPrimitive(
        manager.getPrimitiveType(), key, keyData.getTypeUrl());
    assertTrue(primitive instanceof EncryptThenAuthenticate);
  },

  async testGetPrimitiveMacFromAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager.getKeyType(), manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());

    try {
      await Registry.getPrimitive(Mac, key, keyData.getTypeUrl());
    } catch (e) {
      assertTrue(
          e.toString().includes(ExceptionText.getPrimitiveBadPrimitive()));
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitives method
  async testGetPrimitivesNullKeysetHandle() {
    try {
      await Registry.getPrimitives(DEFAULT_PRIMITIVE_TYPE, null);
    } catch (e) {
      assertEquals(ExceptionText.nullKeysetHandle(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetPrimitivesPrimaryIsTheEnabledKeyWithGivenId() {
    const id = 1;
    const primaryUrl = 'key_type_url_for_primary_key';
    const disabledUrl = 'key_type_url_for_disabled_key';

    const keyset = new PbKeyset();
    keyset.addKey(createKey(
        id, PbOutputPrefixType.TINK, disabledUrl, /* enabled = */ false));
    keyset.addKey(createKey(
        id, PbOutputPrefixType.LEGACY, disabledUrl, /* enabled = */ false));
    keyset.addKey(createKey(
        id, PbOutputPrefixType.RAW, disabledUrl, /* enabled = */ false));
    keyset.addKey(createKey(
        id, PbOutputPrefixType.TINK, primaryUrl, /* enabled = */ true));
    keyset.setPrimaryKeyId(id);

    const keysetHandle = new KeysetHandle(keyset);

    Registry.registerKeyManager(primaryUrl, new DummyKeyManager1(primaryUrl));
    Registry.registerKeyManager(disabledUrl, new DummyKeyManager1(disabledUrl));

    const primitiveSet =
        await Registry.getPrimitives(DEFAULT_PRIMITIVE_TYPE, keysetHandle);
    const primary = primitiveSet.getPrimary();

    // Result of getPrimitive is string, which is the same to typeUrl (see
    // DummyKeyManager1 and registryInitForGetPrimitivesTests).
    assertEquals(primaryUrl, primary.getPrimitive());
  },

  async testGetPrimitivesDisabledKeysShouldBeIgnored() {
    const enabledRawKeysCount = 10;
    const enabledUrl = 'enabled_key_type_url';
    const disabledUrl = 'disabled_key_type_url';

    // Create keyset with both enabled and disabled RAW keys.
    const keyset = new PbKeyset();
    // Add RAW keys with different ids from [1, ENABLED_RAW_KEYS_COUNT].
    for (let i = 0; i < enabledRawKeysCount; i++) {
      keyset.addKey(createKey(
          1 + i, PbOutputPrefixType.RAW, enabledUrl, /* enabled = */ true));
      keyset.addKey(createKey(
          1 + i, PbOutputPrefixType.RAW, disabledUrl, /* enabled = */ false));
    }
    keyset.setPrimaryKeyId(1);
    const keysetHandle = new KeysetHandle(keyset);

    // Register KeyManager (the key manager for enabled keys should be enough).
    Registry.registerKeyManager(enabledUrl, new DummyKeyManager1(enabledUrl));

    // Get primitives and get all raw primitives.
    const primitiveSet =
        await Registry.getPrimitives(DEFAULT_PRIMITIVE_TYPE, keysetHandle);
    const rawPrimitives = primitiveSet.getRawPrimitives();

    // Should return all enabled RAW primitives and nothing else (disabled
    // primitives should not be added into primitive set).
    assertEquals(enabledRawKeysCount, rawPrimitives.length);

    // Test that it returns the correct RAW primitives by using getPrimitive
    // which is set to the string same as typeUrl (see DummyKeyManager1 and
    // registryInitForGetPrimitivesTests).
    for (let i = 0; i < enabledRawKeysCount; ++i) {
      assertEquals(enabledUrl, rawPrimitives[i].getPrimitive());
    }
  },

  async testGetPrimitivesWithCustomKeyManager() {
    // Create keyset handle.
    const keyTypeUrl = 'some_key_type_url';
    const keyId = 1;
    const key = createKey(keyId, PbOutputPrefixType.TINK, keyTypeUrl);

    const keyset = new PbKeyset();
    keyset.addKey(key);
    keyset.setPrimaryKeyId(keyId);

    const keysetHandle = new KeysetHandle(keyset);

    // Register key manager for the given keyType.
    Registry.registerKeyManager(keyTypeUrl, new DummyKeyManager1(keyTypeUrl));

    // Use getPrimitives with custom key manager for the keyType.
    const customPrimitive = 'type_url_corresponding_to_custom_key_manager';
    const customKeyManager = new DummyKeyManager2(keyTypeUrl, customPrimitive);
    const primitiveSet = await Registry.getPrimitives(
        DEFAULT_PRIMITIVE_TYPE, keysetHandle, customKeyManager);

    // Primary should be the entry corresponding to the keyTypeUrl and thus
    // getPrimitive should return customPrimitive.
    const primary = primitiveSet.getPrimary();
    assertEquals(customPrimitive, primary.getPrimitive());
  },

  async testGetPrimitivesKeyWrongPrimitiveType() {
    const goodKeysCount = 10;
    const goodPrimitiveType = Aead;
    const badPrimitiveType = Mac;

    const keyset = new PbKeyset();

    // Add good keys with different KeyTypeUrl and register key manager
    // which provides goodPrimitiveType primitives for each good key.
    for (let i = 0; i < goodKeysCount; i++) {
      const typeUrl = 'good_key_type_url_' + i.toString();
      keyset.addKey(createKey(
          1 + i, PbOutputPrefixType.RAW, typeUrl, /* enabled = */ true));
      Registry.registerKeyManager(
          typeUrl, new DummyKeyManager1(typeUrl, typeUrl, goodPrimitiveType));
    }

    // Add key and corresponding keyManager providing badPrimitiveType.
    const typeUrl = 'bad_key_type_url';
    keyset.addKey(createKey(
        /* id = */ goodKeysCount + 2, PbOutputPrefixType.RAW, typeUrl,
        /* enabled = */ true));
    Registry.registerKeyManager(
        typeUrl, new DummyKeyManager1(typeUrl, typeUrl, badPrimitiveType));

    // Create keyset handle and try to getPrimitives from it. Should throw
    // an exception because KeysetHandle contains key of wrong type.
    keyset.setPrimaryKeyId(1);
    const keysetHandle = new KeysetHandle(keyset);
    try {
      await Registry.getPrimitives(goodPrimitiveType, keysetHandle);
    } catch (e) {
      assertTrue(
          e.toString().includes(ExceptionText.getPrimitiveBadPrimitive()));
    }
  },
});

////////////////////////////////////////////////////////////////////////////////
// helper functions and classes for tests
////////////////////////////////////////////////////////////////////////////////

/**
 * Class which holds texts for each type of exception.
 * @final
 */
class ExceptionText {
  /** @return {string} */
  static notImplemented() {
    return 'CustomError: Not implemented yet.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static newKeyForbidden(keyType) {
    return 'CustomError: New key operation is forbidden for key type: ' +
        keyType + '.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static notRegisteredKeyType(keyType) {
    return 'CustomError: Key manager for key type ' + keyType +
        ' has not been registered.';
  }

  /** @return {string} */
  static nullCatalogue() {
    return 'CustomError: Catalogue cannot be null.';
  }

  /** @return {string} */
  static missingCatalogueName() {
    return 'CustomError: Catalogue must have name.';
  }

  /** @return {string} */
  static overwrittingCatalogueAttempt() {
    return 'CustomError: Catalogue name already exists.';
  }

  /**
   * @param {string} catalogueName
   *
   * @return {string}
   */
  static catalogueMissing(catalogueName) {
    return 'CustomError: Catalogue with name ' + catalogueName +
        ' has not been added.';
  }

  /**
   * @return {string}
   */
  static nullKeyManager() {
    return 'CustomError: Key manager cannot be null.';
  }

  /**
   * @return {string}
   */
  static undefinedKeyType() {
    return 'CustomError: Key type has to be defined.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static keyManagerOverwrittingAttempt(keyType) {
    return 'CustomError: Key manager for key type ' + keyType +
        ' has already been registered and cannot be overwritten.';
  }

  /**
   * @param {string} givenKeyType
   *
   * @return {string}
   */
  static notSupportedKey(givenKeyType) {
    return 'CustomError: The provided key manager does not support '
          + 'key type ' + givenKeyType + '.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static prohibitedChangeToLessRestricted(keyType) {
    return 'CustomError: Key manager for key type ' + keyType +
        ' has already been registered with forbidden new key operation.';
  }

  /**
   * @param {string} keyTypeFromKeyData
   * @param {string} keyTypeParam
   *
   * @return {string}
   */
  static keyTypesAreNotMatching(keyTypeFromKeyData, keyTypeParam) {
    return 'CustomError: Key type is ' + keyTypeParam +
        ', but it is expected to be ' + keyTypeFromKeyData + ' or undefined.';
  }

  /** @return {string} */
  static keyTypeNotDefined() {
    return 'CustomError: Key type has to be specified.';
  }

  /** @return {string} */
  static nullKeysetHandle() {
    return 'CustomError: Keyset handle has to be non-null.';
  }

  /**
   * @return {string}
   */
  static getPrimitiveBadPrimitive() {
    return 'Requested primitive type which is not supported by this ' +
        'key manager.';
  }
}

/**
 * Creates AES CTR HMAC AEAD key format which can be used in tests
 *
 * @return {!PbKeyTemplate}
 */
const createAesCtrHmacAeadTestKeyTemplate = function() {
  const KEY_SIZE = 16;
  const IV_SIZE = 12;
  const TAG_SIZE = 16;

  let keyFormat = new PbAesCtrHmacAeadKeyFormat();

  // set AES CTR key
  keyFormat.setAesCtrKeyFormat(new PbAesCtrKeyFormat());
  keyFormat.getAesCtrKeyFormat().setKeySize(KEY_SIZE);
  keyFormat.getAesCtrKeyFormat().setParams(new PbAesCtrParams());
  keyFormat.getAesCtrKeyFormat().getParams().setIvSize(IV_SIZE);

  // set HMAC key
  keyFormat.setHmacKeyFormat(new PbHmacKeyFormat());
  keyFormat.getHmacKeyFormat().setKeySize(KEY_SIZE);
  keyFormat.getHmacKeyFormat().setParams(new PbHmacParams());
  keyFormat.getHmacKeyFormat().getParams().setHash(PbHashType.SHA1);
  keyFormat.getHmacKeyFormat().getParams().setTagSize(TAG_SIZE);

  let keyTemplate = new PbKeyTemplate();
  keyTemplate.setTypeUrl(
      'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey');
  keyTemplate.setValue(keyFormat.serializeBinary());
  return keyTemplate;
};


// Catalogues classes for testing purposes
/**
 * @final
 * @implements {Catalogue}
 */
class DummyCatalogue1 {
  /**
   * @override
   */
  getKeyManager(typeUrl, primitiveName, minVersion) {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }
}

/**
 * @final
 * @implements {Catalogue}
 */
class DummyCatalogue2 {
  /**
   * @override
   */
  getKeyManager(typeUrl, primitiveName, minVersion) {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }
}

/**
 * @final
 * @implements {Catalogue}
 */
class DummyCatalogue3 {
  /**
   * @override
   */
  getKeyManager(typeUrl, primitiveName, minVersion) {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }
}

// Key factory and key manager classes used in tests
/**
 * @final
 * @implements {KeyManager.KeyFactory}
 */
class DummyKeyFactory {
  /**
   * @param {string} keyType
   * @param {?Uint8Array=} opt_newKeyMethodResult
   */
  constructor(keyType, opt_newKeyMethodResult) {
    /**
     * @const @private {string}
     */
    this.KEY_TYPE_ = keyType;

    if (!opt_newKeyMethodResult) {
      opt_newKeyMethodResult = new Uint8Array(10);
    }

    /**
     * @const @private {!Uint8Array}
     */
    this.NEW_KEY_METHOD_RESULT_ = opt_newKeyMethodResult;
  }

  /**
   * @override
   */
  newKey(keyFormat) {
    const key = new PbAesCtrKey();
    key.setKeyValue(this.NEW_KEY_METHOD_RESULT_);

    return key;
  }

  /**
   * @override
   */
  newKeyData(serializedKeyFormat) {
    let /** PbKeyData */ keyData = new PbKeyData();

    keyData.setTypeUrl(this.KEY_TYPE_);
    keyData.setValue(this.NEW_KEY_METHOD_RESULT_);
    keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL);

    return keyData;
  }
}

const DEFAULT_PRIMITIVE_TYPE = Aead;

/**
 * @final
 * @implements {KeyManager.KeyManager<string>}
 */
class DummyKeyManager1 {
  /**
   * @param {string} keyType
   * @param {?string=} opt_primitive
   * @param {?Object=} opt_primitiveType
   */
  constructor(keyType, opt_primitive, opt_primitiveType) {
    /**
     * @private @const {string}
     */
    this.KEY_TYPE_ = keyType;

    if (!opt_primitive) {
      opt_primitive = keyType;
    }
    /**
     * @private @const {string}
     */
    this.PRIMITIVE_ = opt_primitive;
    /**
     * @private @const {!KeyManager.KeyFactory}
     */
    this.KEY_FACTORY_ = new DummyKeyFactory(keyType);

    if (!opt_primitiveType) {
      opt_primitiveType = DEFAULT_PRIMITIVE_TYPE;
    }
    /**
     * @private @const {!Object}
     */
    this.PRIMITIVE_TYPE_ = opt_primitiveType;
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType !== this.PRIMITIVE_TYPE_) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    return this.PRIMITIVE_;
  }

  /** @override */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return this.KEY_TYPE_;
  }

  /** @override */
  getPrimitiveType() {
    return this.PRIMITIVE_TYPE_;
  }

  /** @override */
  getVersion() {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }

  /** @override */
  getKeyFactory() {
    return this.KEY_FACTORY_;
  }
}

/**
 * @final
 * @implements {KeyManager.KeyManager<string>}
 */
class DummyKeyManager2 {
  /**
   * @param {string} keyType
   * @param {string=} opt_primitive
   * @param {?Object=} opt_primitiveType
   */
  constructor(keyType, opt_primitive, opt_primitiveType) {
    /**
     * @private @const {string}
     */
    this.KEY_TYPE_ = keyType;

    if (!opt_primitive) {
      opt_primitive = keyType;
    }
    /**
     * @private @const {string}
     */
    this.PRIMITIVE_ = opt_primitive;
    /**
     * @private @const {!KeyManager.KeyFactory}
     */
    this.KEY_FACTORY_ = new DummyKeyFactory(keyType);

    if (!opt_primitiveType) {
      opt_primitiveType = DEFAULT_PRIMITIVE_TYPE;
    }
    /**
     * @private @const {!Object}
     */
    this.PRIMITIVE_TYPE_ = opt_primitiveType;
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType !== this.PRIMITIVE_TYPE_) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    return this.PRIMITIVE_;
  }

  /** @override */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return this.KEY_TYPE_;
  }

  /** @override */
  getPrimitiveType() {
    return this.PRIMITIVE_TYPE_;
  }

  /** @override */
  getVersion() {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }

  /** @override */
  getKeyFactory() {
    return this.KEY_FACTORY_;
  }
}


/**
 * Creates a key with the given parameters.
 * The key status is enabled by default.
 *
 * @param {number} id
 * @param {!PbOutputPrefixType} prefixType
 * @param {string} keyTypeUrl
 * @param {boolean=} opt_enabled
 *
 * @return {!PbKeyset.Key}
 */
const createKey = function(id, prefixType, keyTypeUrl, opt_enabled = true) {
  let keyData = new PbKeyData();
  keyData.setTypeUrl(keyTypeUrl);
  keyData.setValue(new Uint8Array(10));
  keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);

  let key = new PbKeyset.Key();
  key.setKeyData(keyData);
  if (opt_enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }
  key.setKeyId(id);
  key.setOutputPrefixType(prefixType);

  return key;
};

/**
 * @final
 * @implements {KeyManager.KeyManager<string>}
 */
class DummyKeyManagerForNewKeyTests {
  /**
   * @param {string} keyType
   * @param {?Uint8Array=} opt_newKeyMethodResult
   */
  constructor(keyType, opt_newKeyMethodResult) {
    /**
     * @private @const {string}
     */
    this.KEY_TYPE_ = keyType;

    /**
     * @private @const {!KeyManager.KeyFactory}
     */
    this.KEY_FACTORY_ = new DummyKeyFactory(keyType, opt_newKeyMethodResult);
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  /** @override */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return this.KEY_TYPE_;
  }

  /** @override */
  getPrimitiveType() {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  /** @override */
  getVersion() {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  /** @override */
  getKeyFactory() {
    return this.KEY_FACTORY_;
  }
}
