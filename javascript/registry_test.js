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
const AeadConfig = goog.require('tink.aead.AeadConfig');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const AesCtrHmacAeadKeyManager = goog.require('tink.aead.AesCtrHmacAeadKeyManager');
const EncryptThenAuthenticate = goog.require('tink.subtle.EncryptThenAuthenticate');
const HybridConfig = goog.require('tink.hybrid.HybridConfig');
const HybridKeyTemplates = goog.require('tink.hybrid.HybridKeyTemplates');
const KeyManager = goog.require('tink.KeyManager');
const Mac = goog.require('tink.Mac');
const PbAesCtrHmacAeadKey = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKey');
const PbAesCtrHmacAeadKeyFormat = goog.require('proto.google.crypto.tink.AesCtrHmacAeadKeyFormat');
const PbAesCtrKey = goog.require('proto.google.crypto.tink.AesCtrKey');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbAesCtrParams = goog.require('proto.google.crypto.tink.AesCtrParams');
const PbEciesAeadHkdfPrivateKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPrivateKey');
const PbEciesAeadHkdfPublicKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPublicKey');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbHmacKeyFormat = goog.require('proto.google.crypto.tink.HmacKeyFormat');
const PbHmacParams = goog.require('proto.google.crypto.tink.HmacParams');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbMessage = goog.require('jspb.Message');
const PrimitiveSet = goog.require('tink.PrimitiveSet');
const Registry = goog.require('tink.Registry');
const SecurityException = goog.require('tink.exception.SecurityException');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');

////////////////////////////////////////////////////////////////////////////////
// tests
////////////////////////////////////////////////////////////////////////////////

testSuite({
  async tearDown() {
    Registry.reset();
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for registerPrimitiveWrapper method
  testRegisterPrimitiveWrapper_emptyManager() {
    try {
      Registry.registerPrimitiveWrapper(null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: primitive wrapper cannot be null', e.toString());
    }
  },

  testRegisterPrimitiveWrapper_overwritingWithSameClass() {
    const primitive = 'somePrimitive';
    const primitiveType = 'somePrimitiveType';
    Registry.registerPrimitiveWrapper(
        new DummyPrimitiveWrapper1(primitive, primitiveType));
    Registry.registerPrimitiveWrapper(
        new DummyPrimitiveWrapper1(primitive, primitiveType));
  },

  testRegisterPrimitiveWrapper_overwritingWithDifferentClass() {
    const primitive = 'somePrimitive';
    const primitiveType = 'somePrimitiveType';
    Registry.registerPrimitiveWrapper(
        new DummyPrimitiveWrapper1(primitive, primitiveType));
    try {
      Registry.registerPrimitiveWrapper(
          new DummyPrimitiveWrapper2(primitive, primitiveType));
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: primitive wrapper for type ' + primitiveType +
              ' has already been registered and cannot be overwritten',
          e.toString());
    }
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for wrap method
  testWrap_shouldWork() {
    const primitive = 'somePrimitive';
    const primitiveType = 'somePrimitiveType';
    const numberOfKeyManagers = 10;

    for (let i = 0; i < numberOfKeyManagers; i++) {
      Registry.registerPrimitiveWrapper(new DummyPrimitiveWrapper1(
          primitive + i.toString(), primitiveType + i.toString()));
    }

    let result;
    for (let i = 0; i < numberOfKeyManagers; i++) {
      result = Registry.wrap(
          new PrimitiveSet.PrimitiveSet(primitiveType + i.toString()));
      assertObjectEquals(primitive + i.toString(), result);
    }
  },

  testWrap_notRegisteredPrimitiveType() {
    const primitiveType = 'does not exist';

    try {
      Registry.wrap(new PrimitiveSet.PrimitiveSet(primitiveType));
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: no primitive wrapper found for type ' + primitiveType,
          e.toString());
    }
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for registerKeyManager  method
  testRegisterKeyManager_emptyManager() {
    try {
      Registry.registerKeyManager(null);
    } catch (e) {
      assertEquals(ExceptionText.nullKeyManager(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  testRegisterKeyManager_overwritingAttempt() {
    const keyType = 'someKeyType';

    try {
      Registry.registerKeyManager(new DummyKeyManager1(keyType));
      Registry.registerKeyManager(new DummyKeyManager2(keyType));
    } catch (e) {
      assertEquals(
          ExceptionText.keyManagerOverwrittingAttempt(keyType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  // Testing newKeyAllowed behavior -- should hold the most restrictive setting.
  async testRegisterKeyManager_moreRestrictiveNewKeyAllowed() {
    const keyType = 'someTypeUrl';
    const keyManager1 = new DummyKeyManager1(keyType);
    const keyTemplate = new PbKeyTemplate().setTypeUrl(keyType);

    //Register the key manager with new_key_allowed and test that it is possible
    //to create a new key data.
    Registry.registerKeyManager(keyManager1);
    await Registry.newKeyData(keyTemplate);

    //Restrict the key manager and test that new key data cannot be created.
    Registry.registerKeyManager(keyManager1, false);
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e) {
      assertEquals(ExceptionText.newKeyForbidden(keyType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testRegisterKeyManager_lessRestrictiveNewKeyAllowed() {
    const keyType = 'someTypeUrl';
    const keyManager1 = new DummyKeyManager1(keyType);
    const keyTemplate = new PbKeyTemplate().setTypeUrl(keyType);

    Registry.registerKeyManager(keyManager1, false);

    // Re-registering key manager with less restrictive setting should not be
    // possible and the restriction has to be still true (i.e. new key data
    // cannot be created).
    try {
      Registry.registerKeyManager(keyManager1);
      fail('An exception should be thrown.');
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
  testGetKeyManager_shouldWork() {
    const numberOfKeyManagers = 10;
    let keyManagers1 = [];
    let keyManagers2 = [];

    for (let i = 0; i < numberOfKeyManagers; i++) {
      keyManagers1.push(new DummyKeyManager1('someKeyType' + i.toString()));
      keyManagers2.push(new DummyKeyManager2('otherKeyType' + i.toString()));

      Registry.registerKeyManager(keyManagers1[i]);
      Registry.registerKeyManager(keyManagers2[i]);
    }

    let result;
    for (let i = 0; i < numberOfKeyManagers; i++) {
      result = Registry.getKeyManager(keyManagers1[i].getKeyType());
      assertObjectEquals(keyManagers1[i], result);

      result = Registry.getKeyManager(keyManagers2[i].getKeyType());
      assertObjectEquals(keyManagers2[i], result);
    }
  },

  testGetKeyManager_notRegisteredKeyType() {
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
  async testNewKeyData_noManagerForGivenKeyType() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const differentKeyType = 'otherKeyType';
    const keyTemplate = new PbKeyTemplate().setTypeUrl(differentKeyType);

    Registry.registerKeyManager(keyManager1);
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

  async testNewKeyData_newKeyDisallowed() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const keyTemplate =
        new PbKeyTemplate().setTypeUrl(keyManager1.getKeyType());

    Registry.registerKeyManager(keyManager1, false);
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

  async testNewKeyData_newKeyAllowed() {
    const /** !Array<string> */ keyTypes = [];
    for (let i = 0; i < 10; i++) {
      keyTypes.push('someKeyType' + i.toString());
    }

    const keyTypesLength = keyTypes.length;
    for (let i = 0; i < keyTypesLength; i++) {
      Registry.registerKeyManager(new DummyKeyManager1(keyTypes[i]), true);
    }

    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate().setTypeUrl(keyTypes[i]);
      const result = await Registry.newKeyData(keyTemplate);
      assertEquals(keyTypes[i], result.getTypeUrl());
    }
  },

  async testNewKeyData_newKeyIsAllowedAutomatically() {
    const /** !Array<string> */ keyTypes = [];
    for (let i = 0; i < 10; i++) {
      keyTypes.push('someKeyType' + i.toString());
    }

    const keyTypesLength = keyTypes.length;
    for (let i = 0; i < keyTypesLength; i++) {
      Registry.registerKeyManager(new DummyKeyManager1(keyTypes[i]));
    }

    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate().setTypeUrl(keyTypes[i]);
      const result = await Registry.newKeyData(keyTemplate);
      assertEquals(keyTypes[i], result.getTypeUrl());
    }
  },

  async testNewKeyData_withAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
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
    const keyTemplate = new PbKeyTemplate().setTypeUrl(notRegisteredKeyType);

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
    const keyTemplate = new PbKeyTemplate().setTypeUrl(keyManager.getKeyType());
    Registry.registerKeyManager(keyManager, /* opt_newKeyAllowed = */ false);

    try {
      await Registry.newKey(keyTemplate);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.newKeyForbidden(keyManager.getKeyType()), e.toString());
    }
  },

  async testNewKey_shouldWork() {
    const /** !Array<string> */ keyTypes = [];
    const /** !Array<!Uint8Array> */ newKeyMethodResult = [];
    const keyTypesLength = 10;

    // Add some keys to Registry.
    for (let i = 0; i < keyTypesLength; i++) {
      keyTypes.push('someKeyType' + i.toString());
      newKeyMethodResult.push(new Uint8Array([i + 1]));

      Registry.registerKeyManager(
          new DummyKeyManagerForNewKeyTests(keyTypes[i], newKeyMethodResult[i]),
          /* newKeyAllowed = */ true);
    }

    // For every keyType verify that it calls new key method of the
    // corresponding KeyManager (KeyFactory).
    for (let i = 0; i < keyTypesLength; i++) {
      const keyTemplate = new PbKeyTemplate().setTypeUrl(keyTypes[i]);

      const key =
          /** @type {!PbAesCtrKey} */ (await Registry.newKey(keyTemplate));

      // The new key method of DummyKeyFactory returns an AesCtrKey which
      // KeyValue is set to corresponding value in newKeyMethodResult.
      assertEquals(newKeyMethodResult[i], key.getKeyValue());
    }
  },

  async testNewKey_withAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
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
  async testGetPrimitive_differentKeyTypes() {
    const keyDataType = 'key_data_key_type_url';
    const anotherType = 'another_key_type_url';
    const keyData = new PbKeyData().setTypeUrl(keyDataType);

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

  async testGetPrimitive_withoutDefiningKeyType() {
    // Get primitive from key proto without key type.
    try {
      await Registry.getPrimitive(null, new PbMessage);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.keyTypeNotDefined(), e.toString());
    }
  },

  async testGetPrimitive_missingKeyManager() {
    const keyDataType = 'key_data_key_type_url';
    const keyData = new PbKeyData().setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(null, keyData);
    } catch (e) {
      assertEquals(
          ExceptionText.notRegisteredKeyType(keyDataType), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetPrimitive_fromAesCtrHmacAeadKeyData() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);

    const primitive =
        await Registry.getPrimitive(manager.getPrimitiveType(), keyData);
    assertTrue(primitive instanceof EncryptThenAuthenticate);
  },

  async testGetPrimitive_fromAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());

    const primitive = await Registry.getPrimitive(
        manager.getPrimitiveType(), key, keyData.getTypeUrl());
    assertTrue(primitive instanceof EncryptThenAuthenticate);
  },

  async testGetPrimitive_macFromAesCtrHmacAeadKey() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
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

  testGetPublicKeyData: {
    shouldRunTests() {
      return !userAgent.EDGE;  // b/120286783
    },

    testNotPrivateKeyFactory() {
      AeadConfig.register();
      const notPrivateTypeUrl = AeadConfig.AES_GCM_TYPE_URL;
      try {
        Registry.getPublicKeyData(notPrivateTypeUrl, new Uint8Array(8));
        fail('An exception should be thrown.');
      } catch (e) {
        assertEquals(
            ExceptionText.notPrivateKeyFactory(notPrivateTypeUrl),
            e.toString());
      }
    },

    testInvalidPrivateKeyProtoSerialization() {
      HybridConfig.register();
      const typeUrl = HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE;
      try {
        Registry.getPublicKeyData(typeUrl, new Uint8Array(10));
        fail('An exception should be thrown.');
      } catch (e) {
        assertEquals(ExceptionText.couldNotParse(typeUrl), e.toString());
      }
    },

    async testShouldWork() {
      HybridConfig.register();
      const privateKeyData = await Registry.newKeyData(
          HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
      const privateKey = PbEciesAeadHkdfPrivateKey.deserializeBinary(
          privateKeyData.getValue());

      const publicKeyData = Registry.getPublicKeyData(
          privateKeyData.getTypeUrl(), privateKeyData.getValue_asU8());
      assertEquals(
          publicKeyData.getTypeUrl(),
          HybridConfig.ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE);
      assertEquals(
          publicKeyData.getKeyMaterialType(),
          PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);

      const expectedPublicKey = privateKey.getPublicKey();
      const publicKey = PbEciesAeadHkdfPublicKey.deserializeBinary(
          publicKeyData.getValue_asU8());
      assertObjectEquals(expectedPublicKey, publicKey);
    },
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

  /**
   * @param {string} typeUrl
   * @return {string}
   */
  static notPrivateKeyFactory(typeUrl) {
    return 'CustomError: Key manager for key type ' + typeUrl +
        ' does not have a private key factory.';
  }

  /**
   * @param {string} typeUrl
   * @return {string}
   */
  static couldNotParse(typeUrl) {
    return 'CustomError: Input cannot be parsed as ' + typeUrl + ' key-proto.';
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

  let keyFormat = new PbAesCtrHmacAeadKeyFormat().setAesCtrKeyFormat(
      new PbAesCtrKeyFormat());
  keyFormat.getAesCtrKeyFormat().setKeySize(KEY_SIZE);
  keyFormat.getAesCtrKeyFormat().setParams(new PbAesCtrParams());
  keyFormat.getAesCtrKeyFormat().getParams().setIvSize(IV_SIZE);

  // set HMAC key
  keyFormat.setHmacKeyFormat(new PbHmacKeyFormat());
  keyFormat.getHmacKeyFormat().setKeySize(KEY_SIZE);
  keyFormat.getHmacKeyFormat().setParams(new PbHmacParams());
  keyFormat.getHmacKeyFormat().getParams().setHash(PbHashType.SHA1);
  keyFormat.getHmacKeyFormat().getParams().setTagSize(TAG_SIZE);

  let keyTemplate =
      new PbKeyTemplate()
          .setTypeUrl(
              'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey')
          .setValue(keyFormat.serializeBinary());
  return keyTemplate;
};

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
    const key = new PbAesCtrKey().setKeyValue(this.NEW_KEY_METHOD_RESULT_);

    return key;
  }

  /**
   * @override
   */
  newKeyData(serializedKeyFormat) {
    let keyData =
        new PbKeyData()
            .setTypeUrl(this.KEY_TYPE_)
            .setValue(this.NEW_KEY_METHOD_RESULT_)
            .setKeyMaterialType(PbKeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL);

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

// PrimitiveWrapper classes for testing purposes
/**
 * @final
 * @implements {PrimitiveWrapper<string>}
 */
class DummyPrimitiveWrapper1 {
  /**
   * @param {string} primitive
   * @param {!Object} primitiveType
   */
  constructor(primitive, primitiveType) {
    /**
     * @private @const {string}
     */
    this.PRIMITIVE_ = primitive;

    /**
     * @private @const {!Object}
     */
    this.PRIMITIVE_TYPE_ = primitiveType;
  }

  /**
   * @override
   */
  wrap(primitiveSet) {
    return this.PRIMITIVE_;
  }

  /**
   * @override
   */
  getPrimitiveType() {
    return this.PRIMITIVE_TYPE_;
  }
}

// PrimitiveWrapper classes for testing purposes
/**
 * @final
 * @implements {PrimitiveWrapper<string>}
 */
class DummyPrimitiveWrapper2 {
  /**
   * @param {string} primitive
   * @param {!Object} primitiveType
   */
  constructor(primitive, primitiveType) {
    /**
     * @private @const {string}
     */
    this.PRIMITIVE_ = primitive;

    /**
     * @private @const {!Object}
     */
    this.PRIMITIVE_TYPE_ = primitiveType;
  }

  /**
   * @override
   */
  wrap(primitiveSet) {
    return this.PRIMITIVE_;
  }

  /**
   * @override
   */
  getPrimitiveType() {
    return this.PRIMITIVE_TYPE_;
  }
}
