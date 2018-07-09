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

const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const Catalogue = goog.require('tink.Catalogue');
const EncryptThenAuthenticate = goog.require('tink.subtle.EncryptThenAuthenticate');
const KeyManager = goog.require('tink.KeyManager');
const PbAesCtrHmacAeadKey = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKey');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbAesCtrParams = goog.require('proto.google.crypto.tink.AesCtrParams');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbHmacParams = goog.require('proto.google.crypto.tink.HmacParams');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbMessage = goog.require('jspb.Message');
const Registry = goog.require('tink.Registry');
const SecurityException = goog.require('tink.exception.SecurityException');

const testSuite = goog.require('goog.testing.testSuite');

////////////////////////////////////////////////////////////////////////////////
// tests
////////////////////////////////////////////////////////////////////////////////

testSuite({
  async tearDown() {
    await Registry.reset();
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for addCatalogue method
  async testAddCatalogueNullCatalogue() {
    try {
      await Registry.addCatalogue('some catalogue', null);
    } catch (e) {
      assertEquals(ExceptionText.nullCatalogue(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddCatalogueEmptyName() {
    try {
      await Registry.addCatalogue('', new DummyCatalogue1());
    } catch (e) {
      assertEquals(ExceptionText.missingCatalogueName(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddCatalogueOverwritingAttempt() {
    try {
        await Registry.addCatalogue('some catalogue', new DummyCatalogue1());
        await Registry.addCatalogue('some catalogue', new DummyCatalogue2());
    } catch (e) {
      assertEquals(ExceptionText.overwrittingCatalogueAttempt(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testAddFewCatalogues() {
    for (let i = 0; i < 10; i++) {
      await Registry.addCatalogue('first'+i.toString(), new DummyCatalogue1());
      await Registry.addCatalogue('second'+i.toString(), new DummyCatalogue2());
      await Registry.addCatalogue('third'+i.toString(), new DummyCatalogue3());
    }
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getCatalogue method
  async testGetCatalogueMissingCatalogue() {
    const name = 'first';

    try {
      await Registry.getCatalogue(name);
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
      const result = await Registry.getCatalogue(catalogueNames[i]);
      assertTrue(result instanceof DummyCatalogue1);
    }
  },



  /////////////////////////////////////////////////////////////////////////////
  // tests for registerKeyManager  method
  async testRegisterKeyManagerEmptyManager() {
    try {
      await Registry.registerKeyManager('some key type', null);
    } catch (e) {
      assertEquals(ExceptionText.nullKeyManager(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testRegisterKeyManagerUndefinedKeyType() {
    try {
      await Registry.registerKeyManager(
          '', new DummyKeyManager1('some_key_type'));
    } catch (e) {
      assertEquals(ExceptionText.undefinedKeyType(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testRegisterKeyManagerOverwritingAttempt() {
    const keyType = 'someKeyType';

    try {
      await Registry.registerKeyManager(keyType, new DummyKeyManager1(keyType));
      await Registry.registerKeyManager(keyType, new DummyKeyManager2(keyType));
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
      await Registry.registerKeyManager(
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

    await Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1);
    await Registry.registerKeyManager(
        keyManager2.getKeyType(), keyManager2, false);
  },

  // Testing newKeyAllowed behavior -- should hold the most restrictive setting.
  async testRegisterKeyManagerMoreRestrictiveNewKeyAllowed() {
    const keyType = 'someTypeUrl';
    const keyManager1 = new DummyKeyManager1(keyType);
    const keyTemplate = new PbKeyTemplate();
    keyTemplate.setTypeUrl(keyType);

    //Register the key manager with new_key_allowed and test that it is possible
    //to create a new key data.
    await Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1);
    await Registry.newKeyData(keyTemplate);

    //Restrict the key manager and test that new key data cannot be created.
    await Registry.registerKeyManager(
        keyManager1.getKeyType(), keyManager1, false);
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

    await Registry.registerKeyManager(
        keyManager1.getKeyType(), keyManager1, false);

    // Re-registering key manager with less restrictive setting should not be
    // possible and the restriction has to be still true (i.e. new key data
    // cannot be created).
    try {
      await Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1);
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

      await Registry.registerKeyManager(
          keyManagers1[i].getKeyType(), keyManagers1[i]);
      await Registry.registerKeyManager(
          keyManagers2[i].getKeyType(), keyManagers2[i]);
    }

    let result;
    for (let i = 0; i < numberOfKeyManagers; i++) {
      result = await Registry.getKeyManager(keyManagers1[i].getKeyType());
      assertObjectEquals(keyManagers1[i], result);

      result = await Registry.getKeyManager(keyManagers2[i].getKeyType());
      assertObjectEquals(keyManagers2[i], result);
    }
  },

  async testGetKeyManagerNotRegisteredKeyType() {
    const keyType = 'some_key_type';

    try {
      await Registry.getKeyManager(keyType);
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

    await Registry.registerKeyManager(keyManager1.getKeyType(), keyManager1);
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

    await Registry.registerKeyManager(
        keyManager1.getKeyType(), keyManager1, false);
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

    for (let i = 0; i < keyTypes.length; i++) {
      await Registry.registerKeyManager(
          keyTypes[i], new DummyKeyManager1(keyTypes[i]), true);
    }

    for (let i = 0; i < keyTypes.length; i++) {
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

    for (let i = 0; i < keyTypes.length; i++) {
      await Registry.registerKeyManager(
          keyTypes[i], new DummyKeyManager1(keyTypes[i]));
    }

    for (let i = 0; i < keyTypes.length; i++) {
      const keyTemplate = new PbKeyTemplate();
      keyTemplate.setTypeUrl(keyTypes[i]);
      const result = await Registry.newKeyData(keyTemplate);
      assertEquals(keyTypes[i], result.getTypeUrl());
    }
  },

  async testNewKeyDataWithAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    await Registry.registerKeyManager(manager.getKeyType(), manager);
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
  // tests for getPrimitive method
  async testGetPrimitiveDifferentKeyTypes() {
    const keyDataType = 'key_data_type';
    const anotherType = 'another_type';
    const keyData = new PbKeyData();
    keyData.setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(keyData, anotherType);
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
      await Registry.getPrimitive(new PbMessage);
    } catch (e) {
      assertEquals(ExceptionText.keyTypeNotDefined(), e.toString());
    }

    // Get primitive from serialized key proto without key type.
    try {
      await Registry.getPrimitive(new Uint8Array(10));
    } catch (e) {
      assertEquals(ExceptionText.keyTypeNotDefined(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetPrimitiveMissingKeyManager() {
    const keyDataType = 'key_data_type';
    const keyData = new PbKeyData();
    keyData.setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(keyData);
    } catch (e) {
      assertEquals(
          ExceptionText.notRegisteredKeyType(keyDataType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetPrimitiveFromAesCtrHmacAeadKeyData() {
    const manager = new AesCtrHmacAeadKeyManager();
    await Registry.registerKeyManager(manager.getKeyType(), manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);

    const primitive = await Registry.getPrimitive(keyData);
    assertTrue(primitive instanceof EncryptThenAuthenticate);
  },

  async testGetPrimitiveFromAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    await Registry.registerKeyManager(manager.getKeyType(), manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());

    const primitive = await Registry.getPrimitive(key, keyData.getTypeUrl());
    assertTrue(primitive instanceof EncryptThenAuthenticate);
  },

  // TODO implement getPrimitive for serialized key proto and then unable
  async testGetPrimitiveFromSerializedAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    await Registry.registerKeyManager(manager.getKeyType(), manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const serializedKey = keyData.getValue();

//    const primitive = await Registry.getPrimitive(
//        serializedKey, keyData.getTypeUrl());
    try {
      await Registry.getPrimitive(serializedKey, keyData.getTypeUrl());
    } catch (e) {
      assertEquals(ExceptionText.notImplemented(), e.toString());
    }
    // assertTrue(primitive instanceof EncryptThenAuthenticate);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitives method
  async testGetPrimitives() {
    try {
      await Registry.getPrimitives();
    } catch (e) {
      assertEquals(ExceptionText.notImplemented(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
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
   */
  constructor(keyType) {
    /**
     * @const @private {string}
     */
    this.KEY_TYPE_ = keyType;
  }

  /**
   * @override
   */
  async newKey(keyFormat) {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }

  /**
   * @override
   */
  async newKeyData(serializedKeyFormat) {
    let /** PbKeyData */ keyData = new PbKeyData();

    keyData.setTypeUrl(this.KEY_TYPE_);
    keyData.setValue(new Uint8Array(10));
    keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL);

    return keyData;
  }
}

/**
 * @final
 * @implements {KeyManager.KeyManager}
 */
class DummyKeyManager1 {
  /**
   * @param {string} keyType
   */
  constructor(keyType) {
    /**
     * @private @const
     */
    this.KEY_TYPE_ = keyType;
    /**
     * @private @const
     */
    this.KEY_FACTORY_ = new DummyKeyFactory(keyType);
  }

  /** @override */
  getPrimitive(key) {
    throw new SecurityException('Not implemented, only for testing purposes.');
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
 * @implements {KeyManager.KeyManager}
 */
class DummyKeyManager2 {
  /**
   * @param {string} keyType
   */
  constructor(keyType) {
    /**
     * @private @const
     */
    this.KEY_TYPE_ = keyType;
  }

  /** @override */
  getPrimitive(key) {
    throw new SecurityException('Not implemented, only for testing purposes.');
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
  getVersion() {
    throw new SecurityException('Not implemented, only for testing purposes.');
  }

  /** @override */
  getKeyFactory() {
    return this.KEY_FACTORY_;
  }
}
