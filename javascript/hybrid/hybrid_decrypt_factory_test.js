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

goog.module('tink.hybrid.HybridDecryptFactoryTest');
goog.setTestOnly('tink.hybrid.HybridDecryptFactoryTest');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const Bytes = goog.require('tink.subtle.Bytes');
const HybridDecrypt = goog.require('tink.HybridDecrypt');
const HybridDecryptFactory = goog.require('tink.hybrid.HybridDecryptFactory');
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

  async testGetPrimitive_nullKeysetHandle() {
    try {
      await HybridDecryptFactory.getPrimitive(null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.nullKeysetHandle(), e.toString());
    }
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
      await HybridDecryptFactory.getPrimitive(keysetHandle);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.keyTypeCorrespondingToBadPrimitive(), e.toString());
    }
  },

  async testGetPrimitive_encryptionShouldWork() {
    const newKeyId = 0xFFFFFFFF;
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    // Preparing encryption primitive (from keyset containing just one public
    // key with ID newKeyId). Use this primitive to obtain a ciphertext.
    const hybridEncrypt = await getEncryptPrimitive(newKeyId, ciphertextSuffix);
    const plaintext = Random.randBytes(10);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);

    // Make corresponding private key with ID newKeyId and register a key
    // manager for that key.
    const newKeyTypeUrl = 'NEW_PRIVATE_KEY_TYPE_URL';
    const newKey = createKey(
        newKeyId, PbOutputPrefixType.TINK, /* enabled = */ true, newKeyTypeUrl);
    const decryptKeyManager =
        new DummyDecryptKeyManager(newKeyTypeUrl, ciphertextSuffix);
    Registry.registerKeyManager(decryptKeyManager);

    // Prepare a keyset for decryption (containing the private key created above
    // and some other dummy keys).
    const decryptKeyset = createKeysetAndInitializeRegistry();
    decryptKeyset.addKey(newKey);
    const decryptKeysetHandle = new KeysetHandle(decryptKeyset);

    // Use HybridDecryptFactory to get the primitive which should decrypt the
    // ciphertext (as it contains the prepared key).
    const hybridDecrypt =
        await HybridDecryptFactory.getPrimitive(decryptKeysetHandle);
    const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

    // Test that the ciphertext was properly decrypted.
    assertObjectEquals(plaintext, decryptedCiphertext);
  },

  async testGetPrimitive_withCustomKeyManager() {
    const newKeyId = 0xFFFFFFFF;
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);

    // Preparing encryption primitive (from keyset containing just one public
    // key with ID newKeyId). Use this primitive to obtain a ciphertext.
    const hybridEncrypt = await getEncryptPrimitive(newKeyId, ciphertextSuffix);
    const plaintext = Random.randBytes(10);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);

    // Create a private key with ID newKeyId and register a key manager for that
    // key. The key manager registered in Registry should not be able to decrypt
    // the ciphertext.
    const newKeyTypeUrl = 'NEW_PRIVATE_KEY_TYPE_URL';
    const newKey = createKey(
        newKeyId, PbOutputPrefixType.TINK, /* enabled = */ true, newKeyTypeUrl);
    const decryptKeyManager = new DummyDecryptKeyManager(
        newKeyTypeUrl, new Uint8Array([1, 1, 1, 0xFF]));
    Registry.registerKeyManager(decryptKeyManager);

    // Prepare a keyset for decryption (containing the private key created above
    // and some other dummy keys).
    const decryptKeyset = createKeysetAndInitializeRegistry();
    decryptKeyset.addKey(newKey);
    const decryptKeysetHandle = new KeysetHandle(decryptKeyset);

    // Use HybridDecryptFactory to get the HybridDecrypt primitive from the
    // prepared keyset (without using custom key manager) and test that it
    // cannot be used for encryption (as the custom manager has to be used
    // to properly decrypt the ciphertext).
    const hybridDecryptWithoutCustomManager =
        await HybridDecryptFactory.getPrimitive(decryptKeysetHandle);
    try {
      await hybridDecryptWithoutCustomManager.decrypt(ciphertext);
    } catch (e) {
    }

    // Create custom key manager and use DecryptFactory with customKeyManager to
    // get a primitive which may be used for ciphertext decryption.
    const customKeyManager =
        new DummyDecryptKeyManager(newKeyTypeUrl, ciphertextSuffix);
    const hybridDecryptWithCustomManager =
        await HybridDecryptFactory.getPrimitive(
            decryptKeysetHandle, customKeyManager);
    const decryptedCiphertext =
        await hybridDecryptWithCustomManager.decrypt(ciphertext);

    // Test that the ciphertext was properly decrypted.
    assertObjectEquals(plaintext, decryptedCiphertext);
  },

  async testGetPrimitive_contextInfoArgumentShouldBePassed() {
    const newKeyId = 0xFFFFFFFF;
    const ciphertextSuffix = new Uint8Array([0, 0, 0, 0xFF]);
    const contextInfo = new Uint8Array([1, 2, 3, 4, 5]);

    // Preparing encryption primitive (from keyset containing just one public
    // key with ID newKeyId). Use this primitive to obtain a ciphertext.
    const hybridEncrypt = await getEncryptPrimitive(newKeyId, ciphertextSuffix);
    const plaintext = Random.randBytes(10);
    const ciphertext = await hybridEncrypt.encrypt(plaintext, contextInfo);

    // Make corresponding private key with ID newKeyId and register a key
    // manager for that key.
    const newKeyTypeUrl = 'NEW_PRIVATE_KEY_TYPE_URL';
    const newKey = createKey(
        newKeyId, PbOutputPrefixType.TINK, /* enabled = */ true, newKeyTypeUrl);
    const decryptKeyManager =
        new DummyDecryptKeyManager(newKeyTypeUrl, ciphertextSuffix);
    Registry.registerKeyManager(decryptKeyManager);

    // Prepare a keyset for decryption (containing the private key created above
    // and some other dummy keys) and get decrypting primitive.
    const decryptKeyset = createKeysetAndInitializeRegistry();
    decryptKeyset.addKey(newKey);
    const decryptKeysetHandle = new KeysetHandle(decryptKeyset);
    const hybridDecrypt =
        await HybridDecryptFactory.getPrimitive(decryptKeysetHandle);

    // Without contextInfo the decryption should fail.
    let failed = false;
    try {
      await hybridDecrypt.decrypt(ciphertext);
    } catch (e) {
      failed = true;
    }
    if (!failed) {
      fail('Decryption should fail.');
    }

    // With contextInfo it should work properly.
    const decryptedCiphertext =
        await hybridDecrypt.decrypt(ciphertext, contextInfo);
    assertObjectEquals(plaintext, decryptedCiphertext);
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
 * The function also register DummyKeyManager providing HybridDecrypt primitives
 * for each keyType added to the keyset.
 *
 * @param {number=} opt_numberOfKeys
// * @return {{encryptKeyset: !PbKeyset, decryptKeyset: !PbKeyset}}
 * @return {!PbKeyset}
 */
const createKeysetAndInitializeRegistry = function(opt_numberOfKeys = 15) {
  const numberOfKeyTypes = 5;
  const keyTypePrefix = 'HYBRID_DECRYPT_KEY_TYPE';

  for (let i = 0; i < numberOfKeyTypes; i++) {
    const typeUrl = keyTypePrefix + i.toString();
    const managerCiphertextSuffix = new Uint8Array([0, 0, i]);
    Registry.registerKeyManager(
        new DummyDecryptKeyManager(typeUrl, managerCiphertextSuffix));
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
  /** @override*/
  async encrypt(plaintext, opt_associatedData) {
    const result = Bytes.concat(plaintext, this.ciphertextSuffix_);
    if (opt_associatedData) {
      return Bytes.concat(result, opt_associatedData);
    }
    return result;
  }
}

/**
 * @implements {HybridDecrypt}
 * @final
 */
class DummyHybridDecrypt {
  /** @param {!Uint8Array} ciphertextSuffix */
  constructor(ciphertextSuffix) {
    /** @const @private {!Uint8Array} */
    this.ciphertextSuffix_ = ciphertextSuffix;
  }
  /** @override*/
  async decrypt(ciphertext, opt_associatedData) {
    if (opt_associatedData) {
      const ciphertextLen = ciphertext.length;
      const aadLen = opt_associatedData.length;
      const aad = ciphertext.subarray(ciphertextLen - aadLen, ciphertextLen);

      if (!Bytes.isEqual(opt_associatedData, aad)) {
        throw new SecurityException('Associated data differs.');
      }
      ciphertext = ciphertext.subarray(0, ciphertextLen - aadLen);
    }
    const cipherLen = ciphertext.length;
    const suffixLen = this.ciphertextSuffix_.length;
    const plaintext = ciphertext.subarray(0, cipherLen - suffixLen);
    const suffix = ciphertext.subarray(cipherLen - suffixLen, cipherLen);

    if (!Bytes.isEqual(this.ciphertextSuffix_, suffix)) {
      throw new SecurityException('Ciphertext decryption failed.');
    }
    return plaintext;
  }
}

/**
 * @final
 * @implements {KeyManager.KeyManager<HybridEncrypt>}
 */
class DummyEncryptKeyManager {
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

/**
 * @final
 * @implements {KeyManager.KeyManager<HybridDecrypt>}
 */
class DummyDecryptKeyManager {
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

  /** @override */
  async getPrimitive(primitiveType, key) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    return new DummyHybridDecrypt(this.ciphertextSuffix_);
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
    return HybridDecrypt;
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

/**
 * Make an encryption primitive (from keyset containing just one public key with
 * ID newKeyId).
 *
 * @param {number} newKeyId
 * @param {!Uint8Array} ciphertextSuffix
 *
 * @return {!Promise<!HybridEncrypt>}
 */
const getEncryptPrimitive = async function(newKeyId, ciphertextSuffix) {
  const encryptKeyset = new PbKeyset();
  const encryptKeyTypeUrl = 'NEW_PUBLIC_KEY_TYPE_URL';
  const encryptKey = createKey(
      newKeyId, PbOutputPrefixType.TINK, /* enabled = */ true,
      encryptKeyTypeUrl);
  encryptKeyset.addKey(encryptKey);
  encryptKeyset.setPrimaryKeyId(newKeyId);
  const encryptKeyManager =
      new DummyEncryptKeyManager(encryptKeyTypeUrl, ciphertextSuffix);
  Registry.registerKeyManager(encryptKeyManager);
  const encryptKeysetHandle = new KeysetHandle(encryptKeyset);
  return await HybridEncryptFactory.getPrimitive(encryptKeysetHandle);
};
