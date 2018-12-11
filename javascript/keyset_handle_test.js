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

goog.module('tink.KeysetHandleTest');
goog.setTestOnly('tink.KeysetHandleTest');

const Aead = goog.require('tink.Aead');
const AeadConfig = goog.require('tink.aead.AeadConfig');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const Mac = goog.require('tink.Mac');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const Registry = goog.require('tink.Registry');
const SecurityException = goog.require('tink.exception.SecurityException');
const testSuite = goog.require('goog.testing.testSuite');
const {createKeyset} = goog.require('tink.testUtils');

testSuite({
  setUp() {
    AeadConfig.register();
  },

  async tearDown() {
    await Registry.reset();
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for constructor
  async testConstructorNullKeyset() {
    try {
      new KeysetHandle(null);
    } catch (e) {
      assertEquals(
          'CustomError: Keyset should be non null and must contain at least one key.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testConstructorKeysetWithEmptyListOfKeys() {
    const keyset = new PbKeyset();
    keyset.setKeyList([]);
    try {
      new KeysetHandle(keyset);
    } catch (e) {
      assertEquals(
          'CustomError: Keyset should be non null and must contain at least one key.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testConstructorShouldWork() {
    const keyset = createKeyset();
    new KeysetHandle(keyset);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getKeyset method

  async testGetKeyset() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    const result = keysetHandle.getKeyset();
    assertObjectEquals(keyset, result);
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for read method
  async testRead() {
    try {
      await KeysetHandle.read(null, null);
    } catch (e) {
      assertEquals(
          'CustomError: KeysetHandle -- read: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for generateNew method
  async testGenerateNew() {
    try {
      await KeysetHandle.generateNew(null);
    } catch (e) {
      assertEquals(
          'CustomError: KeysetHandle -- generateNew: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for write method
  async testWrite() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    try {
      await keysetHandle.write(null, null);
    } catch (e) {
      assertEquals(
          'CustomError: KeysetHandle -- write: Not implemented yet.',
          e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method

  async testGetPrimitive_nullKPrimitiveType() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    try {
      await keysetHandle.getPrimitive(null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: primitive type must be non-null', e.toString());
    }
  },

  async testGetPrimitive() {
    const keyset = createKeysetAndInitializeRegistry();
    const keysetHandle = new KeysetHandle(keyset);

    const aead = await keysetHandle.getPrimitive(Aead);

    // Test the aead primitive returned by getPrimitive method.
    const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6]);
    const ciphertext = await aead.encrypt(plaintext);
    const decryptedText = await aead.decrypt(ciphertext);

    assertObjectEquals(plaintext, decryptedText);
  },

  async testGetPrimitive_customKeyManager() {
    const keyset = createKeysetAndInitializeRegistry();

    // Add a new key with a new key type associated to custom key manager
    // to the keyset.
    const customKeyTypeUrl = 'new_custom_aead_key_type';
    const customKeyId = 0xFFFFFFFF;
    const customKey = createKey(
        customKeyId, PbOutputPrefixType.RAW, customKeyTypeUrl,
        /* enabled = */ true);
    keyset.addKey(customKey);
    const keysetHandle = new KeysetHandle(keyset);

    // Register some key manager with the custom key type.
    const notCustomPrimitiveIdentifier =
        new Uint8Array([customKeyId, customKeyId]);
    Registry.registerKeyManager(new DummyKeyManager(
        customKeyTypeUrl, notCustomPrimitiveIdentifier, Aead));

    // Create a custom key manager and get a primitive corresponding to
    // customKey by getPrimitive method of custom key manager.
    const primitive = new DummyAead(new Uint8Array([customKeyId]));
    const customKeyManager =
        new DummyKeyManager(customKeyTypeUrl, primitive, Aead);
    const customAead = await customKeyManager.getPrimitive(Aead, customKey);


    // Use customAead to encrypt the data.
    const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6]);
    const ciphertext = await customAead.encrypt(plaintext);

    // Check that aead from Registry (i.e. not using CustomKeyManager) fails to
    // decrypt the ciphertext.
    const aeadFromRegistry = await keysetHandle.getPrimitive(Aead);
    try {
      await aeadFromRegistry.decrypt(ciphertext);
      fail('An exception should be thrown here.');
    } catch (e) {
    }

    // Check that if customKeyManager is used, when getting the primitive from
    // keyset handle, then the newly created primitive correctly decrypts the
    // ciphertext.
    const aead = await keysetHandle.getPrimitive(Aead, customKeyManager);
    const decryptedText = await aead.decrypt(ciphertext);

    assertObjectEquals(plaintext, decryptedText);
  },

  async testGetPrimitive_keysetContainsKeyCorrespondingToDifferentPrimitive() {
    const keyset = createKeysetAndInitializeRegistry();

    // Add new key with new key type url to the keyset and register a key
    // manager providing Mac primitives with this key.
    const macKeyTypeUrl = 'mac_key_type_1';
    const macKeyId = 0xFFFFFFFF;
    const macKey = createKey(
        macKeyId, PbOutputPrefixType.TINK, macKeyTypeUrl, /* enabled = */ true);
    keyset.addKey(macKey);
    const primitive = new DummyAead(new Uint8Array([0xFF]));
    Registry.registerKeyManager(
        new DummyKeyManager(macKeyTypeUrl, primitive, Mac));

    const keysetHandle = new KeysetHandle(keyset);

    try {
      await keysetHandle.getPrimitive(Aead);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: Requested primitive type which is not supported by ' +
              'this key manager.',
          e.toString());
    }
  },

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitiveSet_ method

  async testGetPrimitiveSet_primaryKeyIsTheEnabledKeyWithGivenId() {
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

    Registry.registerKeyManager(
        new DummyKeyManager(primaryUrl, primaryUrl + 'primitive', Aead));
    Registry.registerKeyManager(
        new DummyKeyManager(disabledUrl, disabledUrl + 'primitive', Aead));

    const primitiveSet = await keysetHandle.getPrimitiveSet_(Aead);
    const primary = primitiveSet.getPrimary();

    // Result of getPrimitive is string which is the same as typeUrl +
    // 'primitive'.
    assertEquals(primaryUrl + 'primitive', primary.getPrimitive());
  },

  async testGetPrimitiveSet_disabledKeysShouldBeIgnored() {
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
    Registry.registerKeyManager(
        new DummyKeyManager(enabledUrl, enabledUrl + 'primitive', Aead));

    // Get primitives and get all raw primitives.
    const primitiveSet = await keysetHandle.getPrimitiveSet_(Aead);
    const rawPrimitives = primitiveSet.getRawPrimitives();

    // Should return all enabled RAW primitives and nothing else (disabled
    // primitives should not be added into primitive set).
    assertEquals(enabledRawKeysCount, rawPrimitives.length);

    // Test that it returns the correct RAW primitives by using getPrimitive
    // which is set to the string same as typeUrl + 'primitive'.
    for (let i = 0; i < enabledRawKeysCount; ++i) {
      assertEquals(enabledUrl + 'primitive', rawPrimitives[i].getPrimitive());
    }
  },

  async testGetPrimitiveSet_withCustomKeyManager() {
    // Create keyset handle.
    const keyTypeUrl = 'some_key_type_url';
    const keyId = 1;
    const key = createKey(
        keyId, PbOutputPrefixType.TINK, keyTypeUrl, true /* enabled */);

    const keyset = new PbKeyset();
    keyset.addKey(key);
    keyset.setPrimaryKeyId(keyId);

    const keysetHandle = new KeysetHandle(keyset);

    // Register key manager for the given keyType.
    Registry.registerKeyManager(
        new DummyKeyManager(keyTypeUrl, keyTypeUrl + 'primitive', Aead));

    // Use getPrimitives with custom key manager for the keyType.
    const customPrimitive = 'type_url_corresponding_to_custom_key_manager';
    const customKeyManager =
        new DummyKeyManager(keyTypeUrl, customPrimitive, Aead);
    const primitiveSet =
        await keysetHandle.getPrimitiveSet_(Aead, customKeyManager);

    // Primary should be the entry corresponding to the keyTypeUrl and thus
    // getPrimitive should return customPrimitive.
    const primary = primitiveSet.getPrimary();
    assertEquals(customPrimitive, primary.getPrimitive());
  },
});

/**
 * Function for creating keys for testing purposes.
 *
 * @param {number} keyId
 * @param {!PbOutputPrefixType} outputPrefix
 * @param {string} keyTypeUrl
 * @param {boolean} enabled
 *
 * @return {!PbKeyset.Key}
 */
const createKey = function(keyId, outputPrefix, keyTypeUrl, enabled) {
  let key = new PbKeyset.Key();

  if (enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }

  key.setOutputPrefixType(outputPrefix);
  key.setKeyId(keyId);

  const keyData = new PbKeyData();
  keyData.setTypeUrl(keyTypeUrl);
  keyData.setValue(new Uint8Array(0));
  keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.SYMMETRIC);
  key.setKeyData(keyData);

  return key;
};

/**
 * Function for creating keysets for testing purposes.
 * Primary has id 1.
 *
 * The function also register DummyKeyManager providing primitives for each
 * keyType added to the Keyset.
 *
 * @param {?number=} opt_numberOfKeys
 *
 * @return {!PbKeyset}
 */
const createKeysetAndInitializeRegistry = function(opt_numberOfKeys = 15) {
  const numberOfKeyTypes = 5;
  const keyTypePrefix = 'key_type_';

  for (let i = 0; i < numberOfKeyTypes; i++) {
    const typeUrl = keyTypePrefix + i.toString();
    Registry.registerKeyManager(
        new DummyKeyManager(typeUrl, new DummyAead(new Uint8Array([i])), Aead));
  }

  const keyset = new PbKeyset();

  for (let i = 1; i < opt_numberOfKeys; i++) {
    const keyType = keyTypePrefix + (i % numberOfKeyTypes).toString();
    let /** @type{!PbOutputPrefixType} */ outputPrefix;
    switch (i % 3) {
      case 0:
        outputPrefix = PbOutputPrefixType.TINK;
        break;
      case 1:
        outputPrefix = PbOutputPrefixType.LEGACY;
        break;
      default:
        outputPrefix = PbOutputPrefixType.RAW;
    }
    // There are no primitives added to PrimitiveSet for disabled keys, thus
    // they are quite rarely added into the Keyset.
    const key = createKey(i, outputPrefix, keyType, /* enabled = */ i % 7 < 6);
    keyset.addKey(key);

    keyset.setPrimaryKeyId(1);
    return keyset;
  }
};

/**
 * @implements {Aead}
 * @final
 */
class DummyAead {
  /**
   * @param {!Uint8Array} primitiveIdentifier
   */
  constructor(primitiveIdentifier) {
    /** @private @const {!Uint8Array} */
    this.primitiveIdentifier_ = primitiveIdentifier;
  }

  /** @override*/
  // Encrypt method just append the primitive identifier to plaintext.
  async encrypt(plaintext, opt_associatedData) {
    const result =
        new Uint8Array(plaintext.length + this.primitiveIdentifier_.length);
    result.set(plaintext, 0);
    result.set(this.primitiveIdentifier_, plaintext.length);
    return result;
  }

  /** @override*/
  // Decrypt method throws an exception whenever ciphertext does not end with
  // primitive identifier, otherwise it returns the first part (without
  // primitive identifier).
  async decrypt(ciphertext, opt_associatedData) {
    const plaintext = ciphertext.subarray(
        0, ciphertext.length - this.primitiveIdentifier_.length);
    const primitiveIdentifier = ciphertext.subarray(
        ciphertext.length - this.primitiveIdentifier_.length,
        ciphertext.length);

    if ([...primitiveIdentifier].toString() !=
        [...this.primitiveIdentifier_].toString()) {
      throw new SecurityException('Ciphertext decryption failed.');
    }

    return plaintext;
  }
}

// Key factory and key manager classes used in tests.
/**
 * @final
 * @implements {KeyManager.KeyFactory}
 */
class DummyKeyFactory {
  /**
   * @override
   */
  newKey(keyFormat) {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  /**
   * @override
   */
  newKeyData(serializedKeyFormat) {
    throw new SecurityException('Not implemented, function is not needed.');
  }
}

/**
 * @final
 * @implements {KeyManager.KeyManager<!Object>}
 */
class DummyKeyManager {
  /**
   * @param {string} keyType
   * @param {!Object} primitive
   * @param {!Object} primitiveType
   */
  constructor(keyType, primitive, primitiveType) {
    /**
     * @private @const {string}
     */
    this.KEY_TYPE_ = keyType;

    /**
     * @private @const {!Object}
     */
    this.PRIMITIVE_ = primitive;

    /**
     * @private @const {!KeyManager.KeyFactory}
     */
    this.KEY_FACTORY_ = new DummyKeyFactory();

    /**
     * @private @const {!Object}
     */
    this.PRIMITIVE_TYPE_ = primitiveType;
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType != this.getPrimitiveType()) {
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
    throw new SecurityException('Not implemented, function is not needed.');
  }

  /** @override */
  getKeyFactory() {
    throw new SecurityException('Not implemented, function is not needed.');
  }
}
