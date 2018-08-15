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

goog.module('tink.aead.AeadFactoryTest');
goog.setTestOnly('tink.aead.AeadFactoryTest');

const Aead = goog.require('tink.Aead');
const AeadFactory = goog.require('tink.aead.AeadFactory');
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

testSuite({
  async tearDown() {
    await Registry.reset();
  },

  async testGetPrimitive_nullKeysetHandle() {
    try {
      await AeadFactory.getPrimitive(null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.nullKeysetHandle(), e.toString());
    }
  },

  async testGetPrimitive_badType() {
    const keyset = createKeysetAndInitializeRegistry();

    // Add new key with new key type url to the keyset and register a key
    // manager providing Mac primitives with this key.
    const macKeyTypeUrl = 'mac_key_type_1';
    const macKeyId = 0xFFFFFFFF;
    const macKey = createKey(
        macKeyId, PbOutputPrefixType.TINK, /* enabled = */ true, macKeyTypeUrl);
    keyset.addKey(macKey);
    const primitiveIdentifier = new Uint8Array([0xFF]);
    Registry.registerKeyManager(
        new DummyKeyManager(macKeyTypeUrl, primitiveIdentifier, Mac));

    const keysetHandle = new KeysetHandle(keyset);

    try {
      await AeadFactory.getPrimitive(keysetHandle);
    } catch (e) {
      assertEquals(
          ExceptionText.keyTypeCorrespondingToBadPrimitive(), e.toString());
      return;
    }
    fail('An exception should be thrown.');
  },

  async testGetPrimitive_shouldWork() {
    const keyset = createKeysetAndInitializeRegistry();
    const keysetHandle = new KeysetHandle(keyset);

    const aead = await AeadFactory.getPrimitive(keysetHandle);

    // Test the aead primitive returned by getPrimitive method.
    const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6]);
    const ciphertext = await aead.encrypt(plaintext);
    const decryptedText = await aead.decrypt(ciphertext);

    assertObjectEquals(plaintext, decryptedText);
  },

  async testGetPrimitive_withCustomKeyManager_shouldWork() {
    const keyset = createKeysetAndInitializeRegistry();

    // Add a new key with a new key type associated to custom key manager
    // to the keyset.
    const customKeyTypeUrl = 'new_custom_aead_key_type';
    const customKeyId = 0xFFFFFFFF;
    const customKey = createKey(
        customKeyId, PbOutputPrefixType.RAW,
        /* enabled = */ true, customKeyTypeUrl);
    keyset.addKey(customKey);
    const keysetHandle = new KeysetHandle(keyset);

    // Register some key manager with the custom key type.
    const notCustomPrimitiveIdentifier =
        new Uint8Array([customKeyId, customKeyId]);
    Registry.registerKeyManager(
        new DummyKeyManager(customKeyTypeUrl, notCustomPrimitiveIdentifier));

    // Create a custom key manager and get a primitive corresponding to
    // customKey by getPrimitive method of custom key manager.
    const customPrimitiveIdentifier = new Uint8Array([customKeyId]);
    const customKeyManager =
        new DummyKeyManager(customKeyTypeUrl, customPrimitiveIdentifier);
    const customAead = await customKeyManager.getPrimitive(Aead, customKey);


    // Use customAead to encrypt the data.
    const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6]);
    const ciphertext = await customAead.encrypt(plaintext);

    // Check that aead from Registry (i.e. not using CustomKeyManager) fails to
    // decrypt the ciphertext.
    const aeadFromRegistry = await AeadFactory.getPrimitive(keysetHandle);
    try {
      await aeadFromRegistry.decrypt(ciphertext);
      fail('An exception should be thrown here.');
    } catch (e) {
    }

    // Check that if customKeyManager is used, when getting the primitive from
    // AeadFactory, then the newly created primitive correctly decrypts the
    // ciphertext.
    const aead = await AeadFactory.getPrimitive(keysetHandle, customKeyManager);
    const decryptedText = await aead.decrypt(ciphertext);

    assertObjectEquals(plaintext, decryptedText);
  },
});


// Helper classes and functions
class ExceptionText {
  /**
   * @return {string}
   */
  static nullKeysetHandle() {
    return 'CustomError: Keyset handle has to be non-null.';
  }

  /**
   * @return {string}
   */
  static keyTypeCorrespondingToBadPrimitive() {
    return 'CustomError: Requested primitive type which is not supported by ' +
        'this key manager.';
  }
}


/**
 * Function for creating keys for testing purposes.
 *
 * @param {number} keyId
 * @param {!PbOutputPrefixType} outputPrefix
 * @param {boolean} enabled
 * @param {string} keyTypeUrl
 *
 * @return {!PbKeyset.Key}
 */
const createKey = function(keyId, outputPrefix, enabled, keyTypeUrl) {
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
 * The function also register DummyKeyManager providing Aead primitives for each
 * keyType added to the Keyset.
 *
 * @param {?number=} opt_numberOfKeys
 *
 * @return {!PbKeyset}
 */
const createKeysetAndInitializeRegistry = function(opt_numberOfKeys = 15) {
  const numberOfKeyTypes = 5;
  const keyTypePrefix = 'aead_key_type_';

  for (let i = 0; i < numberOfKeyTypes; i++) {
    const typeUrl = keyTypePrefix + i.toString();
    Registry.registerKeyManager(
        new DummyKeyManager(typeUrl, new Uint8Array([i])));
  }

  const keyset = new PbKeyset();

  for (let i = 1; i < opt_numberOfKeys; i++) {
    let /** @type{PbOutputPrefixType} */ outputPrefix;
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
    const keyType = keyTypePrefix + (i % numberOfKeyTypes).toString();
    // There are no primitives added to PrimitiveSet for disabled keys, thus
    // they are quite rarely added into the Keyset.
    const key = createKey(i, outputPrefix, /* enabled = */ i % 7 < 6, keyType);
    keyset.addKey(key);
  }

  keyset.setPrimaryKeyId(1);
  return keyset;
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
   * @param {!Uint8Array} primitiveIdentifier
   * @param {?Object=} opt_primitiveType
   */
  constructor(keyType, primitiveIdentifier, opt_primitiveType) {
    /**
     * @private @const {string}
     */
    this.KEY_TYPE_ = keyType;

    /**
     * @private @const {!Uint8Array}
     */
    this.PRIMITIVE_IDENTIFIER_ = primitiveIdentifier;

    /**
     * @private @const {!KeyManager.KeyFactory}
     */
    this.KEY_FACTORY_ = new DummyKeyFactory();

    if (!opt_primitiveType) {
      opt_primitiveType = Aead;
    }
    /**
     * @private @const {!Object}
     */
    this.PRIMITIVE_TYPE_ = opt_primitiveType;
  }

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    return new DummyAead(this.PRIMITIVE_IDENTIFIER_);
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
