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

const {Aead} = goog.require('google3.third_party.tink.javascript.aead.internal.aead');
const {AeadConfig} = goog.require('google3.third_party.tink.javascript.aead.aead_config');
const {AeadKeyTemplates} = goog.require('google3.third_party.tink.javascript.aead.aead_key_templates');
const {AesCtrHmacAeadKeyManager} = goog.require('google3.third_party.tink.javascript.aead.aes_ctr_hmac_aead_key_manager');
const {EncryptThenAuthenticate} = goog.require('google3.third_party.tink.javascript.subtle.encrypt_then_authenticate');
const HybridConfig = goog.require('tink.hybrid.HybridConfig');
const HybridKeyTemplates = goog.require('tink.hybrid.HybridKeyTemplates');
const KeyManager = goog.require('google3.third_party.tink.javascript.internal.key_manager');
const {Mac} = goog.require('google3.third_party.tink.javascript.mac.internal.mac');
const PrimitiveSet = goog.require('google3.third_party.tink.javascript.internal.primitive_set');
const {PrimitiveWrapper} = goog.require('google3.third_party.tink.javascript.internal.primitive_wrapper');
const Registry = goog.require('google3.third_party.tink.javascript.internal.registry');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const {PbAesCtrHmacAeadKey, PbAesCtrHmacAeadKeyFormat, PbAesCtrKey, PbAesCtrKeyFormat, PbAesCtrParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbHashType, PbHmacKeyFormat, PbHmacParams, PbKeyData, PbKeyTemplate, PbMessage} = goog.require('google3.third_party.tink.javascript.internal.proto');

////////////////////////////////////////////////////////////////////////////////
// tests
////////////////////////////////////////////////////////////////////////////////

describe('registry test', function() {
  afterEach(function() {
    Registry.reset();
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for registerPrimitiveWrapper method
  it('register primitive wrapper, overwriting with same class', function() {
    Registry.registerPrimitiveWrapper(new DummyPrimitiveWrapper1(
        new DummyPrimitive1Impl1(), DummyPrimitive1));
    Registry.registerPrimitiveWrapper(new DummyPrimitiveWrapper1(
        new DummyPrimitive1Impl2(), DummyPrimitive1));
  });

  it('register primitive wrapper, overwriting with different class',
     function() {
       /** @implements {PrimitiveWrapper<DummyPrimitive1>} */
       class DummyPrimitiveWrapper1Alternative {
         /** @override */
         wrap() {
           throw new Error();
         }
         /** @override */
         getPrimitiveType() {
           return DummyPrimitive1;
         }
       }
       Registry.registerPrimitiveWrapper(new DummyPrimitiveWrapper1(
           new DummyPrimitive1Impl1(), DummyPrimitive1));
       try {
         Registry.registerPrimitiveWrapper(
             new DummyPrimitiveWrapper1Alternative());
         fail('An exception should be thrown.');
       } catch (e) {
         expect(e.toString())
             .toBe(
                 'SecurityException: primitive wrapper for type ' +
                 DummyPrimitive1 +
                 ' has already been registered and cannot be overwritten');
       }
     });

  /////////////////////////////////////////////////////////////////////////////
  // tests for wrap method
  it('wrap, should work', function() {
    const p1 = new DummyPrimitive1Impl1();
    const p2 = new DummyPrimitive2Impl();
    Registry.registerPrimitiveWrapper(
        new DummyPrimitiveWrapper1(p1, DummyPrimitive1));
    Registry.registerPrimitiveWrapper(
        new DummyPrimitiveWrapper2(p2, DummyPrimitive2));

    expect(Registry.wrap(new PrimitiveSet.PrimitiveSet(DummyPrimitive1)))
        .toBe(p1);
    expect(Registry.wrap(new PrimitiveSet.PrimitiveSet(DummyPrimitive2)))
        .toBe(p2);
  });

  it('wrap, not registered primitive type', function() {
    expect(() => {
      Registry.wrap(new PrimitiveSet.PrimitiveSet(DummyPrimitive1));
    }).toThrowError('no primitive wrapper found for type ' +
              DummyPrimitive1);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for registerKeyManager  method
  it('register key manager, overwriting attempt', function() {
    const keyType = 'someKeyType';

    try {
      Registry.registerKeyManager(new DummyKeyManager1(keyType));
      Registry.registerKeyManager(new DummyKeyManager2(keyType));
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.keyManagerOverwrittingAttempt(keyType));
      return;
    }
    fail('An exception should be thrown.');
  });

  // Testing newKeyAllowed behavior -- should hold the most restrictive setting.
  it('register key manager, more restrictive new key allowed',
     async function() {
       const keyType = 'someTypeUrl';
       const keyManager1 = new DummyKeyManager1(keyType);
       const keyTemplate = new PbKeyTemplate().setTypeUrl(keyType);

       // Register the key manager with new_key_allowed and test that it is
       // possible to create a new key data.
       Registry.registerKeyManager(keyManager1);
       await Registry.newKeyData(keyTemplate);

       // Restrict the key manager and test that new key data cannot be created.
       Registry.registerKeyManager(keyManager1, false);
       try {
         await Registry.newKeyData(keyTemplate);
       } catch (e) {
         expect(e.toString()).toBe(ExceptionText.newKeyForbidden(keyType));
         return;
       }
       fail('An exception should be thrown.');
     });

  it('register key manager, less restrictive new key allowed',
     async function() {
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
         expect(e.toString())
             .toBe(ExceptionText.prohibitedChangeToLessRestricted(
                 keyManager1.getKeyType()));
       }
       try {
         await Registry.newKeyData(keyTemplate);
       } catch (e) {
         expect(e.toString()).toBe(ExceptionText.newKeyForbidden(keyType));
         return;
       }
       fail('An exception should be thrown.');
     });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getKeyManager method
  it('get key manager, should work', function() {
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
      expect(result).toEqual(keyManagers1[i]);

      result = Registry.getKeyManager(keyManagers2[i].getKeyType());
      expect(result).toEqual(keyManagers2[i]);
    }
  });

  it('get key manager, not registered key type', function() {
    const keyType = 'some_key_type';

    try {
      Registry.getKeyManager(keyType);
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.notRegisteredKeyType(keyType));
      return;
    }
    fail('An exception should be thrown.');
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKeyData method
  it('new key data, no manager for given key type', async function() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const differentKeyType = 'otherKeyType';
    const keyTemplate = new PbKeyTemplate().setTypeUrl(differentKeyType);

    Registry.registerKeyManager(keyManager1);
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.notRegisteredKeyType(differentKeyType));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key data, new key disallowed', async function() {
    const keyManager1 = new DummyKeyManager1('someKeyType');
    const keyTemplate =
        new PbKeyTemplate().setTypeUrl(keyManager1.getKeyType());

    Registry.registerKeyManager(keyManager1, false);
    try {
      await Registry.newKeyData(keyTemplate);
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.newKeyForbidden(keyManager1.getKeyType()));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('new key data, new key allowed', async function() {
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
      expect(result.getTypeUrl()).toBe(keyTypes[i]);
    }
  });

  it('new key data, new key is allowed automatically', async function() {
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
      expect(result.getTypeUrl()).toBe(keyTypes[i]);
    }
  });

  it('new key data, with aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    const keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);

    // Checks that correct AES CTR HMAC AEAD key was returned.
    const keyFormat =
        PbAesCtrHmacAeadKeyFormat.deserializeBinary(keyTemplate.getValue());
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());
    // Check AES CTR key.
    expect(keyFormat.getAesCtrKeyFormat().getKeySize())
        .toBe(key.getAesCtrKey().getKeyValue().length);
    expect(keyFormat.getAesCtrKeyFormat().getParams())
        .toEqual(key.getAesCtrKey().getParams());
    // Check HMAC key.
    expect(keyFormat.getHmacKeyFormat().getKeySize())
        .toBe(key.getHmacKey().getKeyValue().length);
    expect(keyFormat.getHmacKeyFormat().getParams())
        .toEqual(key.getHmacKey().getParams());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for newKey method
  it('new key, no manager for given key type', async function() {
    const notRegisteredKeyType = 'not_registered_key_type';
    const keyTemplate = new PbKeyTemplate().setTypeUrl(notRegisteredKeyType);

    try {
      await Registry.newKey(keyTemplate);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.notRegisteredKeyType(notRegisteredKeyType));
    }
  });

  it('new key, new key disallowed', async function() {
    const keyManager = new DummyKeyManagerForNewKeyTests('someKeyType');
    const keyTemplate = new PbKeyTemplate().setTypeUrl(keyManager.getKeyType());
    Registry.registerKeyManager(keyManager, /* opt_newKeyAllowed = */ false);

    try {
      await Registry.newKey(keyTemplate);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.newKeyForbidden(keyManager.getKeyType()));
    }
  });

  it('new key, should work', async function() {
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
      expect(key.getKeyValue()).toBe(newKeyMethodResult[i]);
    }
  });

  it('new key, with aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    const keyTemplate = AeadKeyTemplates.aes256CtrHmacSha256();

    const key =
        /** @type{!PbAesCtrHmacAeadKey} */ (await Registry.newKey(keyTemplate));

    // Checks that correct AES CTR HMAC AEAD key was returned.
    const keyFormat =
        PbAesCtrHmacAeadKeyFormat.deserializeBinary(keyTemplate.getValue());
    // Check AES CTR key.
    expect(keyFormat.getAesCtrKeyFormat().getKeySize())
        .toBe(key.getAesCtrKey().getKeyValue().length);
    expect(keyFormat.getAesCtrKeyFormat().getParams())
        .toEqual(key.getAesCtrKey().getParams());
    // Check HMAC key.
    expect(keyFormat.getHmacKeyFormat().getKeySize())
        .toBe(key.getHmacKey().getKeyValue().length);
    expect(keyFormat.getHmacKeyFormat().getParams())
        .toEqual(key.getHmacKey().getParams());
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method
  it('get primitive, different key types', async function() {
    const keyDataType = 'key_data_key_type_url';
    const anotherType = 'another_key_type_url';
    const keyData = new PbKeyData().setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(Aead, keyData, anotherType);
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.keyTypesAreNotMatching(keyDataType, anotherType));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('get primitive, without defining key type', async function() {
    // Get primitive from key proto without key type.
    try {
      await Registry.getPrimitive(Aead, new PbMessage);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.keyTypeNotDefined());
    }
  });

  it('get primitive, missing key manager', async function() {
    const keyDataType = 'key_data_key_type_url';
    const keyData = new PbKeyData().setTypeUrl(keyDataType);

    try {
      await Registry.getPrimitive(Aead, keyData);
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.notRegisteredKeyType(keyDataType));
      return;
    }
    fail('An exception should be thrown.');
  });

  it('get primitive, from aes ctr hmac aead key data', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);

    const primitive =
        await Registry.getPrimitive(manager.getPrimitiveType(), keyData);
    expect(primitive instanceof EncryptThenAuthenticate).toBe(true);
  });

  it('get primitive, from aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());

    const primitive = await Registry.getPrimitive(
        manager.getPrimitiveType(), key, keyData.getTypeUrl());
    expect(primitive instanceof EncryptThenAuthenticate).toBe(true);
  });

  it('get primitive, mac from aes ctr hmac aead key', async function() {
    const manager = new AesCtrHmacAeadKeyManager();
    Registry.registerKeyManager(manager);
    let keyTemplate = createAesCtrHmacAeadTestKeyTemplate();
    const keyData = await Registry.newKeyData(keyTemplate);
    const key = PbAesCtrHmacAeadKey.deserializeBinary(keyData.getValue());

    try {
      await Registry.getPrimitive(Mac, key, keyData.getTypeUrl());
    } catch (e) {
      expect(e.toString().includes(ExceptionText.getPrimitiveBadPrimitive()))
          .toBe(true);
      return;
    }
    fail('An exception should be thrown.');
  });

  describe('get public key data', function() {
    it('not private key factory', function() {
      AeadConfig.register();
      const notPrivateTypeUrl = AeadConfig.AES_GCM_TYPE_URL;
      try {
        Registry.getPublicKeyData(notPrivateTypeUrl, new Uint8Array(8));
        fail('An exception should be thrown.');
      } catch (e) {
        expect(e.toString())
            .toBe(ExceptionText.notPrivateKeyFactory(notPrivateTypeUrl));
      }
    });

    it('invalid private key proto serialization', function() {
      HybridConfig.register();
      const typeUrl = HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE;
      try {
        Registry.getPublicKeyData(typeUrl, new Uint8Array(10));
        fail('An exception should be thrown.');
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.couldNotParse(typeUrl));
      }
    });

    it('should work', async function() {
      HybridConfig.register();
      const privateKeyData = await Registry.newKeyData(
          HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
      const privateKey = PbEciesAeadHkdfPrivateKey.deserializeBinary(
          privateKeyData.getValue());

      const publicKeyData = Registry.getPublicKeyData(
          privateKeyData.getTypeUrl(), privateKeyData.getValue_asU8());
      expect(HybridConfig.ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE)
          .toBe(publicKeyData.getTypeUrl());
      expect(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .toBe(publicKeyData.getKeyMaterialType());

      const expectedPublicKey = privateKey.getPublicKey();
      const publicKey = PbEciesAeadHkdfPublicKey.deserializeBinary(
          publicKeyData.getValue_asU8());
      expect(publicKey).toEqual(expectedPublicKey);
    });
  });
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
    return 'SecurityException: Not implemented yet.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static newKeyForbidden(keyType) {
    return 'SecurityException: New key operation is forbidden for key type: ' +
        keyType + '.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static notRegisteredKeyType(keyType) {
    return 'SecurityException: Key manager for key type ' + keyType +
        ' has not been registered.';
  }

  /**
   * @return {string}
   */
  static nullKeyManager() {
    return 'SecurityException: Key manager cannot be null.';
  }

  /**
   * @return {string}
   */
  static undefinedKeyType() {
    return 'SecurityException: Key type has to be defined.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static keyManagerOverwrittingAttempt(keyType) {
    return 'SecurityException: Key manager for key type ' + keyType +
        ' has already been registered and cannot be overwritten.';
  }

  /**
   * @param {string} givenKeyType
   *
   * @return {string}
   */
  static notSupportedKey(givenKeyType) {
    return 'SecurityException: The provided key manager does not support ' +
        'key type ' + givenKeyType + '.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static prohibitedChangeToLessRestricted(keyType) {
    return 'SecurityException: Key manager for key type ' + keyType +
        ' has already been registered with forbidden new key operation.';
  }

  /**
   * @param {string} keyTypeFromKeyData
   * @param {string} keyTypeParam
   *
   * @return {string}
   */
  static keyTypesAreNotMatching(keyTypeFromKeyData, keyTypeParam) {
    return 'SecurityException: Key type is ' + keyTypeParam +
        ', but it is expected to be ' + keyTypeFromKeyData + ' or undefined.';
  }

  /** @return {string} */
  static keyTypeNotDefined() {
    return 'SecurityException: Key type has to be specified.';
  }

  /** @return {string} */
  static nullKeysetHandle() {
    return 'SecurityException: Keyset handle has to be non-null.';
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
    return 'SecurityException: Key manager for key type ' + typeUrl +
        ' does not have a private key factory.';
  }

  /**
   * @param {string} typeUrl
   * @return {string}
   */
  static couldNotParse(typeUrl) {
    return 'SecurityException: Input cannot be parsed as ' + typeUrl +
        ' key-proto.';
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

// Primitive abstract types for testing purposes.
/** @record */
class DummyPrimitive1 {
  /** @return {number} */
  operation1() {}
}
/** @record */
class DummyPrimitive2 {
  /** @return {string} */
  operation2() {}
}

// Primitive implementations for testing purposes.
/** @implements {DummyPrimitive1} */
class DummyPrimitive1Impl1 {
  /** @override */
  operation1() {
    return 1;
  }
}
/** @implements {DummyPrimitive1} */
class DummyPrimitive1Impl2 {
  /** @override */
  operation1() {
    return 2;
  }
}
/** @implements {DummyPrimitive2} */
class DummyPrimitive2Impl {
  /** @override */
  operation2() {
    return 'dummy';
  }
}

const DEFAULT_PRIMITIVE_TYPE = Aead;

/**
 * @final
 * @implements {KeyManager.KeyManager<!DummyPrimitive1>}
 */
class DummyKeyManager1 {
  /**
   * @param {string} keyType
   * @param {?DummyPrimitive1=} opt_primitive
   * @param {?Object=} opt_primitiveType
   */
  constructor(keyType, opt_primitive, opt_primitiveType) {
    /**
     * @private @const {string}
     */
    this.KEY_TYPE_ = keyType;

    if (!opt_primitive) {
      opt_primitive = new DummyPrimitive1Impl1();
    }
    /**
     * @private @const {!DummyPrimitive1}
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
 * @implements {KeyManager.KeyManager<!DummyPrimitive2>}
 */
class DummyKeyManager2 {
  /**
   * @param {string} keyType
   * @param {!DummyPrimitive2=} opt_primitive
   * @param {?Object=} opt_primitiveType
   */
  constructor(keyType, opt_primitive, opt_primitiveType) {
    /**
     * @private @const {string}
     */
    this.KEY_TYPE_ = keyType;

    if (!opt_primitive) {
      opt_primitive = new DummyPrimitive2Impl();
    }
    /**
     * @private @const {!DummyPrimitive2}
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
 * @implements {PrimitiveWrapper<DummyPrimitive1>}
 */
class DummyPrimitiveWrapper1 {
  /**
   * @param {!DummyPrimitive1} primitive
   * @param {!Object} primitiveType
   */
  constructor(primitive, primitiveType) {
    /**
     * @private @const {!DummyPrimitive1}
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
 * @implements {PrimitiveWrapper<DummyPrimitive2>}
 */
class DummyPrimitiveWrapper2 {
  /**
   * @param {!DummyPrimitive2} primitive
   * @param {!Object} primitiveType
   */
  constructor(primitive, primitiveType) {
    /**
     * @private @const {!DummyPrimitive2}
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
