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

goog.module('tink.hybrid.HybridEncryptFactoryTest');
goog.setTestOnly('tink.hybrid.HybridEncryptFactoryTest');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const Bytes = goog.require('tink.subtle.Bytes');
const HybridEncrypt = goog.require('tink.HybridEncrypt');
const HybridEncryptFactory = goog.require('tink.hybrid.HybridEncryptFactory');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyStatusType = goog.require('proto.google.crypto.tink.KeyStatusType');
const PbKeyset = goog.require('proto.google.crypto.tink.Keyset');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const SecurityException = goog.require('tink.exception.SecurityException');

const testSuite = goog.require('goog.testing.testSuite');

testSuite({
  setUp() {
    AeadConfig.register();
  },

  tearDown() {
    Registry.reset();
  },

  async testGetPrimitive_keysetContainsKeyCorrespondingToDifferentPrimitive() {
    const keyset = createKeysetAndInitializeRegistry();

    // Add new key for AEAD primitive into keyset.
    const keyId = 0xFFFFFFFF;
    const aeadKey = createKey(
        keyId, PbOutputPrefixType.TINK, /* enabled = */ true,
        AeadConfig.AES_GCM_TYPE_URL);
    keyset.addKey(aeadKey);

    const keysetHandle = new KeysetHandle(keyset);
    try {
      await HybridEncryptFactory.getPrimitive(keysetHandle);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.keyTypeCorrespondingToBadPrimitive(), e.toString());
    }
  },

  async testGetPrimitive_shouldWork() {
    const keyset = createKeysetAndInitializeRegistry();
    const primaryId = 0xFFFFFFFF;
    const primaryTypeUrl = 'PRIMARY_TYPE_URL';
    const primaryKey = createKey(
        primaryId, PbOutputPrefixType.TINK,
        /* enabled = */ true, primaryTypeUrl);
    keyset.addKey(primaryKey);
    keyset.setPrimaryKeyId(primaryId);
    const primaryKeyManager =
        new DummyKeyManager(primaryTypeUrl, new Uint8Array([0, 0, 0, 0xFF]));
    Registry.registerKeyManager(primaryKeyManager);
    const keysetHandle = new KeysetHandle(keyset);

    const hybridEncrypt = await HybridEncryptFactory.getPrimitive(keysetHandle);

    // Test the HybridEncrypt primitive returned by getPrimitive method.
    const plaintext = Random.randBytes(10);
    await hybridEncrypt.encrypt(plaintext);
  },

  async testGetPrimitive_withCustomKeyManager_shouldWork() {
    const keyset = createKeysetAndInitializeRegistry();
    const customId = 0xFFFFFFFF;
    const customTypeUrl = 'TYPE_URL_OF_CUSTOM_KEY_MANAGER';
    const customKey = createKey(
        customId, PbOutputPrefixType.RAW, /* enabled = */ true, customTypeUrl);
    keyset.addKey(customKey);
    // This key has to be set to primary, otherwise corresponding primitive is
    // not used for encryption.
    keyset.setPrimaryKeyId(customId);
    const keysetHandle = new KeysetHandle(keyset);

    const managerInRegistry =
        new DummyKeyManager(customTypeUrl, new Uint8Array([0, 0, 0, 0xFF]));
    Registry.registerKeyManager(managerInRegistry);
    const customManager =
        new DummyKeyManager(customTypeUrl, new Uint8Array([0, 0, 0xFF, 0xFF]));
    const hybridEncrypt =
        await HybridEncryptFactory.getPrimitive(keysetHandle, customManager);

    // Test the HybridEncrypt primitive returned by getPrimitive method.
    const plaintext = Random.randBytes(10);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);

    // Test that the plaintext was encrypted by primitive from custom key
    // manager.
    const primitiveByCustomManager =
        await customManager.getPrimitive(HybridEncrypt, customKey);
    const ciphertextByCustomManager =
        await primitiveByCustomManager.encrypt(plaintext);
    assertObjectEquals(ciphertextByCustomManager, ciphertext);
  },
});


// Helper classes and functions
class ExceptionText {
  /** @return {string} */
  static nullKeysetHandle() {
    return 'CustomError: Keyset handle has to be non-null.';
  }

  /** @return {string} */
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
  keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
  key.setKeyData(keyData);

  return key;
};

/**
 * Function for creating keysets for testing purposes. Primary key has id 1.
 * The function also register DummyKeyManager providing HybridEncrypt primitives
 * for each keyType added to the keyset.
 *
 * @param {number=} opt_numberOfKeys
 * @return {!PbKeyset}
 */
const createKeysetAndInitializeRegistry = function(opt_numberOfKeys = 15) {
  const numberOfKeyTypes = 5;
  const keyTypePrefix = 'HYBRID_ENCRYPT_KEY_TYPE_';

  for (let i = 0; i < numberOfKeyTypes; i++) {
    const typeUrl = keyTypePrefix + i.toString();
    Registry.registerKeyManager(
        new DummyKeyManager(typeUrl, new Uint8Array([0, 0, i])));
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
    // they are rarely added into the Keyset.
    const key = createKey(i, outputPrefix, /* enabled = */ i % 7 < 6, keyType);
    keyset.addKey(key);
  }
  keyset.setPrimaryKeyId(1);
  return keyset;
};

/**
 * @implements {HybridEncrypt}
 * @final
 */
class DummyHybridEncrypt {
  /** @param {!Uint8Array} ciphertextSuffix */
  constructor(ciphertextSuffix) {
    /** @const @private {!Uint8Array} */
    this.ciphertextSuffix_ = ciphertextSuffix;
  }
  // Async is used here just because real primitives returns Promise.
  /** @override*/
  async encrypt(plaintext, opt_associatedData) {
    return Bytes.concat(plaintext, this.ciphertextSuffix_);
  }
}

/**
 * @implements {KeyManager.KeyManager<HybridEncrypt>}
 * @final
 */
class DummyKeyManager {
  /**
   * @param {string} typeUrl
   * @param {!Uint8Array} ciphertextSuffix
   */
  constructor(typeUrl, ciphertextSuffix) {
    /** @const @private {string} */
    this.typeUrl_ = typeUrl;
    /** @const @private {!Uint8Array} */
    this.ciphertextSuffix_ = ciphertextSuffix;
  }

  // Async is used here just because real primitives returns Promise.
  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    return new DummyHybridEncrypt(this.ciphertextSuffix_);
  }

  /** @override */
  doesSupport(keyType) {
    return keyType === this.getKeyType();
  }
  /** @override */
  getKeyType() {
    return this.typeUrl_;
  }
  /** @override */
  getPrimitiveType() {
    return HybridEncrypt;
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
