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

const {Aead} = goog.require('google3.third_party.tink.javascript.aead.internal.aead');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const BinaryKeysetReader = goog.require('tink.BinaryKeysetReader');
const BinaryKeysetWriter = goog.require('tink.BinaryKeysetWriter');
const Bytes = goog.require('tink.subtle.Bytes');
const CleartextKeysetHandle = goog.require('tink.CleartextKeysetHandle');
const HybridConfig = goog.require('tink.hybrid.HybridConfig');
const {HybridDecrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_decrypt');
const {HybridEncrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_encrypt');
const KeyManager = goog.require('tink.KeyManager');
const KeysetHandle = goog.require('tink.KeysetHandle');
const {Mac} = goog.require('google3.third_party.tink.javascript.mac.internal.mac');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const {SecurityException} = goog.require('google3.third_party.tink.javascript.exception.security_exception');
const {PbKeyData, PbKeyMaterialType, PbKeyStatusType, PbKeyset, PbOutputPrefixType} = goog.require('google3.third_party.tink.javascript.internal.proto');
const {createKeyset} = goog.require('google3.third_party.tink.javascript.testing.internal.test_utils');

describe('keyset handle test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s

    HybridConfig.register();
  });

  afterEach(function() {
    Registry.reset();

    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for constructor
  it('constructor keyset with empty list of keys', async function() {
    const keyset = new PbKeyset().setKeyList([]);
    try {
      new KeysetHandle(keyset);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Keyset should be non null and must contain at least one key.');
      return;
    }
    fail('An exception should be thrown.');
  });

  it('constructor should work', async function() {
    const keyset = createKeyset();
    new KeysetHandle(keyset);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getKeyset method

  it('get keyset', async function() {
    const keyset = createKeyset();
    const keysetHandle = new KeysetHandle(keyset);

    const result = keysetHandle.getKeyset();
    expect(result).toEqual(keyset);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for read method
  it('read', async function() {
    const keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
    const keysetHandle = await KeysetHandle.generateNew(keyTemplate);
    const serializedKeyset =
        CleartextKeysetHandle.serializeToBinary(keysetHandle);
    const keysetReader = new BinaryKeysetReader(serializedKeyset);
    const aead = await keysetHandle.getPrimitive(Aead);
    try {
      await KeysetHandle.read(keysetReader, aead);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: KeysetHandle -- read: Not implemented yet.');
      return;
    }
    fail('An exception should be thrown.');
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for generateNew method
  it('generate new', async function() {
    const keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
    const keysetHandle = await KeysetHandle.generateNew(keyTemplate);
    const keyset = keysetHandle.getKeyset();
    expect(1).toBe(keyset.getKeyList().length);

    const key = keyset.getKeyList()[0];
    expect(keyset.getPrimaryKeyId()).toBe(key.getKeyId());
    expect(keyTemplate.getOutputPrefixType()).toBe(key.getOutputPrefixType());
    expect(PbKeyStatusType.ENABLED).toBe(key.getStatus());

    const keyData = key.getKeyData();
    expect(keyTemplate.getTypeUrl()).toBe(keyData.getTypeUrl());

    const aead = await keysetHandle.getPrimitive(Aead);
    const plaintext = Random.randBytes(20);
    const ciphertext = await aead.encrypt(plaintext);
    expect(await aead.decrypt(ciphertext)).toEqual(plaintext);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for write method
  it('write', async function() {
    const keyset = createKeysetAndInitializeRegistry(Aead);
    const keysetHandle = new KeysetHandle(keyset);
    const keysetWriter = new BinaryKeysetWriter();
    const aead = await keysetHandle.getPrimitive(Aead);

    try {
      await keysetHandle.write(keysetWriter, aead);
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: KeysetHandle -- write: Not implemented yet.');
      return;
    }
    fail('An exception should be thrown.');
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitive method

  it('get primitive,  aead', async function() {
    const keyset = createKeysetAndInitializeRegistry(Aead);
    const keysetHandle = new KeysetHandle(keyset);

    const aead = await keysetHandle.getPrimitive(Aead);

    // Test the aead primitive returned by getPrimitive method.
    const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6]);
    const ciphertext = await aead.encrypt(plaintext);
    const decryptedText = await aead.decrypt(ciphertext);

    expect(decryptedText).toEqual(plaintext);
  });

  it('get primitive,  hybrid encrypt', async function() {
    const keyset = createKeysetAndInitializeRegistry(HybridEncrypt);
    const keysetHandle = new KeysetHandle(keyset);

    // Test the HybridEncrypt primitive returned by getPrimitive method.
    const hybridEncrypt = await keysetHandle.getPrimitive(HybridEncrypt);
    const plaintext = Random.randBytes(10);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);
    // DummyHybridEncrypt just appends a ciphertext suffix to the plaintext.
    // Since the primary key id is 1, the ciphertext prefix should also be 1.
    expect(ciphertext)
        .toEqual(Bytes.concat(
            new Uint8Array([
              0, 0, 0, 0, 1
            ]) /* prefix which is 1-byte version + 4-byte primary key id*/,
            plaintext,
            new Uint8Array([1]) /* suffix which is 1-byte primary key id */));
  });

  it('get primitive,  hybrid decrypt', async function() {
    const decryptKeysetHandle =
        new KeysetHandle(createKeysetAndInitializeRegistry(HybridDecrypt));
    const hybridDecrypt = await decryptKeysetHandle.getPrimitive(HybridDecrypt);

    const encryptKeysetHandle =
        new KeysetHandle(createKeysetAndInitializeRegistry(HybridEncrypt));
    const hybridEncrypt = await encryptKeysetHandle.getPrimitive(HybridEncrypt);

    const plaintext = Random.randBytes(10);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);
    const decrypted = await hybridDecrypt.decrypt(ciphertext);

    expect(decrypted).toEqual(plaintext);
  });

  it('get primitive,  aead, custom key manager', async function() {
    const keyset = new PbKeyset();

    // Add a new key with a new key type associated to custom key manager
    // to the keyset.
    const keyTypeUrl = 'new_custom_aead_key_type';
    const keyId = 0xFFFFFFFF;
    const key = createKey(
        keyId, PbOutputPrefixType.TINK, keyTypeUrl,
        /* enabled = */ true);
    keyset.addKey(key);
    keyset.setPrimaryKeyId(keyId);
    const keysetHandle = new KeysetHandle(keyset);

    // Create a custom key manager.
    const customKeyManager = new DummyKeyManager(
        keyTypeUrl, new DummyAead(Random.randBytes(10)), Aead);

    // Encrypt with the primitive returned by customKeyManager.
    const aead = await keysetHandle.getPrimitive(Aead, customKeyManager);
    const plaintext = Random.randBytes(20);
    const ciphertext = await aead.encrypt(plaintext);

    // Register another key manager with the custom key type.
    const managerInRegistry = new DummyKeyManager(
        keyTypeUrl, new DummyAead(Random.randBytes(10)), Aead);
    Registry.registerKeyManager(managerInRegistry);

    // Check that the primitive returned by getPrimitive cannot decrypt the
    // ciphertext. This is because managerInRegistry is different from
    // customKeyManager.
    const aeadFromRegistry = await keysetHandle.getPrimitive(Aead);
    try {
      await aeadFromRegistry.decrypt(ciphertext);
      fail('An exception should be thrown here.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Decryption failed for the given ciphertext.');
    }

    // Check that the primitive returned by getPrimitive with customKeyManager
    // decrypts correctly.
    const aeadFromCustomKeyManager =
        await keysetHandle.getPrimitive(Aead, customKeyManager);
    const decryptedText = await aeadFromCustomKeyManager.decrypt(ciphertext);
    expect(decryptedText).toEqual(plaintext);
  });

  it('get primitive,  hybrid encrypt, custom key manager', async function() {
    const keyset = new PbKeyset();

    // Add a new key with a new key type associated to custom key manager
    // to the keyset.
    const keyTypeUrl = 'new_custom_hybrid_encrypt_key_type';
    const keyId = 0xFFFFFFFF;
    const key = createKey(
        keyId, PbOutputPrefixType.TINK, keyTypeUrl,
        /* enabled = */ true);
    keyset.addKey(key);
    keyset.setPrimaryKeyId(keyId);
    const keysetHandle = new KeysetHandle(keyset);

    // Create a custom key manager.
    const customKeyManager = new DummyKeyManager(
        keyTypeUrl, new DummyHybridEncrypt(Random.randBytes(10)),
        HybridEncrypt);

    // Encrypt with the primitive returned by customKeyManager.
    const customHybridEncrypt =
        await keysetHandle.getPrimitive(HybridEncrypt, customKeyManager);
    const plaintext = Random.randBytes(20);
    const ciphertext = await customHybridEncrypt.encrypt(plaintext);

    // Register another key manager with the custom key type.
    const managerInRegistry = new DummyKeyManager(
        keyTypeUrl, new DummyHybridEncrypt(Random.randBytes(10)),
        HybridEncrypt);
    Registry.registerKeyManager(managerInRegistry);

    // Check that the primitive returned by getPrimitive is not the same as
    // customHybridEncrypt. This is because managerInRegistry is different from
    // customKeyManager.
    const hybridFromRegistry = await keysetHandle.getPrimitive(HybridEncrypt);
    const ciphertext2 = await hybridFromRegistry.encrypt(plaintext);
    expect(ciphertext2).not.toEqual(ciphertext);

    // Check that the primitive returned by getPrimitive with customKeyManager
    // is the same as customHybridEncrypt.
    const hybridEncryptFromCustomKeyManager =
        await keysetHandle.getPrimitive(HybridEncrypt, customKeyManager);
    const ciphertext3 =
        await hybridEncryptFromCustomKeyManager.encrypt(plaintext);
    expect(ciphertext3).toEqual(ciphertext);
  });

  it('get primitive,  hybrid decrypt, custom key manager', async function() {
    // Both private and public keys have the same key id.
    const keyId = 0xFFFFFFFF;

    // Create a public keyset.

    const publicKeyset = new PbKeyset();
    // Add a new key with a new key type associated to custom key manager
    // to the keyset.
    const publicKeyTypeUrl = 'new_custom_hybrid_encrypt_key_type';
    const publicKey = createKey(
        keyId, PbOutputPrefixType.TINK, publicKeyTypeUrl,
        /* enabled = */ true);
    publicKeyset.addKey(publicKey);
    publicKeyset.setPrimaryKeyId(keyId);
    const publicKeysetHandle = new KeysetHandle(publicKeyset);

    // Create a corresponding private keyset.

    const privateKeyset = new PbKeyset();
    // Add a new key with a new key type associated to custom key manager
    // to the keyset.
    const privateKeyTypeUrl = 'new_custom_hybrid_decrypt_key_type';
    const privateKey = createKey(
        keyId, PbOutputPrefixType.TINK, privateKeyTypeUrl,
        /* enabled = */ true);
    privateKeyset.addKey(privateKey);
    privateKeyset.setPrimaryKeyId(keyId);
    const privateKeysetHandle = new KeysetHandle(privateKeyset);

    // DummyHybridEncrypt (and DummyHybridDecrypt) just appends (and removes)
    // a suffix to the plaintext. Create a random suffix that allows to
    // determine which HybridDecrypt object is valid.
    const ciphertextSuffix = Random.randBytes(10);

    // Register a public key manager that uses the legit ciphertext suffix.
    const publicKeyManagerInRegistry = new DummyKeyManager(
        publicKeyTypeUrl, new DummyHybridEncrypt(ciphertextSuffix),
        HybridEncrypt);
    Registry.registerKeyManager(publicKeyManagerInRegistry);

    // Encrypt with the primitive returned by getPrimitive.
    const hybridEncrypt = await publicKeysetHandle.getPrimitive(HybridEncrypt);
    const plaintext = Random.randBytes(20);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);

    // Register a private key manager that uses a random ciphertext suffix.
    const keyManagerWithRandomSuffix = new DummyKeyManager(
        privateKeyTypeUrl, new DummyHybridDecrypt(Random.randBytes(10)),
        HybridDecrypt);
    Registry.registerKeyManager(keyManagerWithRandomSuffix);

    // Check that the primitive returned by getPrimitive cannot decrypt. This is
    // because the ciphertext suffix is different.
    const hybridDecryptFromRegistry =
        await privateKeysetHandle.getPrimitive(HybridDecrypt);
    try {
      await hybridDecryptFromRegistry.decrypt(ciphertext);
      fail('An exception should be thrown here.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: Decryption failed for the given ciphertext.');
    }

    // Create a custom private key manager with the correct ciphertext suffix.
    const customHybridDecryptKeyManager = new DummyKeyManager(
        privateKeyTypeUrl, new DummyHybridDecrypt(ciphertextSuffix),
        HybridDecrypt);

    // Check that the primitive returned by getPrimitive with
    // customHybridDecryptKeyManager can decrypt.
    const customHybridDecrypt = await privateKeysetHandle.getPrimitive(
        HybridDecrypt, customHybridDecryptKeyManager);
    const decrypted = await customHybridDecrypt.decrypt(ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  it('get primitive, keyset contains key corresponding to different primitive',
     async function() {
       const keyset = createKeysetAndInitializeRegistry(Aead);

       // Add new key with new key type url to the keyset and register a key
       // manager providing Mac primitives with this key.
       const macKeyTypeUrl = 'mac_key_type_1';
       const macKeyId = 0xFFFFFFFF;
       const macKey = createKey(
           macKeyId, PbOutputPrefixType.TINK, macKeyTypeUrl,
           /* enabled = */ true);
       keyset.addKey(macKey);
       const primitive = new DummyAead(new Uint8Array([0xFF]));
       Registry.registerKeyManager(
           new DummyKeyManager(macKeyTypeUrl, primitive, Mac));

       const keysetHandle = new KeysetHandle(keyset);

       try {
         await keysetHandle.getPrimitive(Aead);
         fail('An exception should be thrown.');
       } catch (e) {
         expect(e.toString())
             .toBe(
                 'SecurityException: Requested primitive type which is not supported by ' +
                 'this key manager.');
       }
     });

  /////////////////////////////////////////////////////////////////////////////
  // tests for getPrimitiveSet method

  it('get primitive set, primary key is the enabled key with given id',
     async function() {
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

       const primitive = new DummyAead(new Uint8Array(Random.randBytes(10)));
       Registry.registerKeyManager(
           new DummyKeyManager(primaryUrl, primitive, Aead));
       Registry.registerKeyManager(new DummyKeyManager(
           disabledUrl, new DummyAead(new Uint8Array(Random.randBytes(10))),
           Aead));

       const primitiveSet = await keysetHandle.getPrimitiveSet(Aead);
       const primary = primitiveSet.getPrimary();

       expect(primary.getPrimitive()).toBe(primitive);
     });

  it('get primitive set, disabled keys should be ignored', async function() {
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
    const primitive = new DummyAead(new Uint8Array(Random.randBytes(10)));
    Registry.registerKeyManager(
        new DummyKeyManager(enabledUrl, primitive, Aead));

    // Get primitives and get all raw primitives.
    const primitiveSet = await keysetHandle.getPrimitiveSet(Aead);
    const rawPrimitives = primitiveSet.getRawPrimitives();

    // Should return all enabled RAW primitives and nothing else (disabled
    // primitives should not be added into primitive set).
    expect(rawPrimitives.length).toBe(enabledRawKeysCount);

    // Test that it returns the correct RAW primitives by using getPrimitive.
    for (let i = 0; i < enabledRawKeysCount; ++i) {
      expect(rawPrimitives[i].getPrimitive()).toBe(primitive);
    }
  });

  it('get primitive set, with custom key manager', async function() {
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
    const primitive = new DummyAead(new Uint8Array(Random.randBytes(10)));
    Registry.registerKeyManager(
        new DummyKeyManager(keyTypeUrl, primitive, Aead));

    // Use getPrimitives with custom key manager for the keyType.
    const customPrimitive = new DummyAead(new Uint8Array(Random.randBytes(10)));
    const customKeyManager =
        new DummyKeyManager(keyTypeUrl, customPrimitive, Aead);
    const primitiveSet =
        await keysetHandle.getPrimitiveSet(Aead, customKeyManager);

    // Primary should be the entry corresponding to the keyTypeUrl and thus
    // getPrimitive should return customPrimitive.
    const primary = primitiveSet.getPrimary();
    expect(primary.getPrimitive()).toBe(customPrimitive);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for readNoSecret method

  it('read no secret, keyset containing secret key material', function() {
    const secretKeyMaterialTypes = [
      PbKeyMaterialType.SYMMETRIC, PbKeyMaterialType.ASYMMETRIC_PRIVATE,
      PbKeyMaterialType.UNKNOWN_KEYMATERIAL
    ];
    for (let secretKeyMaterialType of secretKeyMaterialTypes) {
      // Create a public keyset.
      const keyset = new PbKeyset();
      for (let i = 0; i < 3; i++) {
        const key = createKey(
            /* keyId = */ i + 1,
            /* outputPrefix = */ PbOutputPrefixType.TINK,
            /* keyTypeUrl = */ 'someType',
            /* enabled = */ (i % 4) < 2,
            /* opt_keyMaterialType */ PbKeyMaterialType.ASYMMETRIC_PUBLIC);
        keyset.addKey(key);
      }
      keyset.setPrimaryKeyId(1);
      const key = createKey(
          /* keyId = */ 0xFFFFFFFF,
          /* outputPrefix = */ PbOutputPrefixType.RAW,
          /* keyTypeUrl = */ 'someType',
          /* enabled = */ true,
          /* opt_keyMaterialType = */ secretKeyMaterialType);
      keyset.addKey(key);
      const reader =
          BinaryKeysetReader.withUint8Array(keyset.serializeBinary());
      try {
        KeysetHandle.readNoSecret(reader);
        fail('An exception should be thrown.');
      } catch (e) {
        expect(e.toString())
            .toBe('SecurityException: Keyset contains secret key material.');
      }
    }
  });

  it('read no secret, should work', function() {
    // Create a public keyset.
    const keyset = new PbKeyset();
    for (let i = 0; i < 3; i++) {
      const key = createKey(
          /* keyId = */ i + 1,
          /* outputPrefix = */ PbOutputPrefixType.TINK,
          /* keyTypeUrl = */ 'someType',
          /* enabled = */ (i % 4) < 2,
          /* opt_keyMaterialType = */ PbKeyMaterialType.ASYMMETRIC_PUBLIC);
      keyset.addKey(key);
    }
    keyset.setPrimaryKeyId(1);

    const reader = BinaryKeysetReader.withUint8Array(keyset.serializeBinary());
    const keysetHandle = KeysetHandle.readNoSecret(reader);

    expect(keysetHandle.getKeyset()).toEqual(keyset);
  });
});

/**
 * Function for creating keys for testing purposes.
 *
 * @param {number} keyId
 * @param {!PbOutputPrefixType} outputPrefix
 * @param {string} keyTypeUrl
 * @param {boolean} enabled
 * @param {!PbKeyMaterialType=} opt_keyMaterialType (default: SYMMETRIC)
 *
 * @return {!PbKeyset.Key}
 */
const createKey = function(
    keyId, outputPrefix, keyTypeUrl, enabled,
    opt_keyMaterialType = PbKeyMaterialType.SYMMETRIC) {
  let key = new PbKeyset.Key();

  if (enabled) {
    key.setStatus(PbKeyStatusType.ENABLED);
  } else {
    key.setStatus(PbKeyStatusType.DISABLED);
  }

  key.setOutputPrefixType(outputPrefix);
  key.setKeyId(keyId);

  const keyData = new PbKeyData()
                      .setTypeUrl(keyTypeUrl)
                      .setValue(new Uint8Array([1]))
                      .setKeyMaterialType(opt_keyMaterialType);
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
 * @param {!Object} primitiveType
 * @param {number=} opt_numberOfKeys
 *
 * @return {!PbKeyset}
 */
const createKeysetAndInitializeRegistry = function(
    primitiveType, opt_numberOfKeys = 15) {
  const numberOfKeyTypes = 5;
  const keyTypePrefix = 'key_type_';

  for (let i = 0; i < numberOfKeyTypes; i++) {
    const typeUrl = keyTypePrefix + i.toString();
    let primitive;
    switch (primitiveType) {
      case HybridDecrypt:
        primitive = new DummyHybridDecrypt(new Uint8Array([i]));
        break;
      case HybridEncrypt:
        primitive = new DummyHybridEncrypt(new Uint8Array([i]));
        break;
      default:
        primitive = new DummyAead(new Uint8Array([i]));
        break;
    }
    Registry.registerKeyManager(
        new DummyKeyManager(typeUrl, primitive, primitiveType));
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
  }

  keyset.setPrimaryKeyId(1);
  return keyset;
};

/**
 * @final
 */
class DummyAead extends Aead {
  /**
   * @param {!Uint8Array} ciphertextSuffix
   */
  constructor(ciphertextSuffix) {
    super();
    /** @private @const {!Uint8Array} */
    this.ciphertextSuffix_ = ciphertextSuffix;
  }

  /** @override*/
  // Encrypt method just append the primitive identifier to plaintext.
  async encrypt(plaintext, opt_associatedData) {
    const result =
        new Uint8Array(plaintext.length + this.ciphertextSuffix_.length);
    result.set(plaintext, 0);
    result.set(this.ciphertextSuffix_, plaintext.length);
    return result;
  }

  /** @override*/
  // Decrypt method throws an exception whenever ciphertext does not end with
  // ciphertext suffix, otherwise it returns the first part (without
  // ciphertext suffix).
  async decrypt(ciphertext, opt_associatedData) {
    const plaintext = ciphertext.subarray(
        0, ciphertext.length - this.ciphertextSuffix_.length);
    const ciphertextSuffix = ciphertext.subarray(
        ciphertext.length - this.ciphertextSuffix_.length, ciphertext.length);

    if ([...ciphertextSuffix].toString() !=
        [...this.ciphertextSuffix_].toString()) {
      throw new SecurityException('Ciphertext decryption failed.');
    }

    return plaintext;
  }
}

/**
 * @final
 */
class DummyHybridEncrypt extends HybridEncrypt {
  /** @param {!Uint8Array} ciphertextSuffix */
  constructor(ciphertextSuffix) {
    super();
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
 * @final
 */
class DummyHybridDecrypt extends HybridDecrypt {
  /** @param {!Uint8Array} ciphertextSuffix */
  constructor(ciphertextSuffix) {
    super();
    /** @const @private {!Uint8Array} */
    this.ciphertextSuffix_ = ciphertextSuffix;
  }
  /** @override*/
  async decrypt(ciphertext, opt_associatedData) {
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
 * @implements {KeyManager.KeyManager<T>}
 * @template T
 */
class DummyKeyManager {
  /**
   * @param {string} keyType
   * @param {T} primitive
   * @param {!Object} primitiveType
   */
  constructor(keyType, primitive, primitiveType) {
    /**
     * @private @const {string}
     */
    this.KEY_TYPE_ = keyType;

    /**
     * @private @const {T}
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
