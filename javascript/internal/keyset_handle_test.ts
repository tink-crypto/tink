/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {Aead} from '../aead';
import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {SecurityException} from '../exception/security_exception';
import {HybridDecrypt, HybridEncrypt} from '../hybrid';
import * as HybridConfig from '../hybrid/hybrid_config';
import {HybridKeyTemplates} from '../hybrid/hybrid_key_templates';
import {Mac} from '../mac';
import * as Bytes from '../subtle/bytes';
import * as Random from '../subtle/random';
import {assertExists, createKeyset} from '../testing/internal/test_utils';

import {BinaryKeysetReader} from './binary_keyset_reader';
import {BinaryKeysetWriter} from './binary_keyset_writer';
import {CleartextKeysetHandle} from './cleartext_keyset_handle';
import * as KeyManager from './key_manager';
import {generateNew, KeysetHandle, read, readNoSecret} from './keyset_handle';
import {PbKeyData, PbKeyMaterialType, PbKeyset, PbKeysetKey, PbKeyStatusType, PbMessage, PbOutputPrefixType} from './proto';
import * as Registry from './registry';
import {Constructor} from './util';

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
    const keysetHandle = await generateNew(keyTemplate);
    const serializedKeyset =
        CleartextKeysetHandle.serializeToBinary(keysetHandle);
    const keysetReader = new BinaryKeysetReader(serializedKeyset);
    const aead = await keysetHandle.getPrimitive<Aead>(Aead);
    try {
      await read(keysetReader, aead);
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
    const keysetHandle = await generateNew(keyTemplate);
    const keyset = keysetHandle.getKeyset();
    expect(1).toBe(keyset.getKeyList().length);

    const key = keyset.getKeyList()[0];
    expect(keyset.getPrimaryKeyId()).toBe(key.getKeyId());
    expect(keyTemplate.getOutputPrefixType()).toBe(key.getOutputPrefixType());
    expect(PbKeyStatusType.ENABLED).toBe(key.getStatus());

    const keyData = assertExists(key.getKeyData());
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
    const aead = await keysetHandle.getPrimitive<Aead>(Aead);

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

    const aead = await keysetHandle.getPrimitive<Aead>(Aead);

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
    const hybridEncrypt =
        await keysetHandle.getPrimitive<HybridEncrypt>(HybridEncrypt);
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
    const hybridDecrypt =
        await decryptKeysetHandle.getPrimitive<HybridDecrypt>(HybridDecrypt);

    const encryptKeysetHandle =
        new KeysetHandle(createKeysetAndInitializeRegistry(HybridEncrypt));
    const hybridEncrypt =
        await encryptKeysetHandle.getPrimitive<HybridEncrypt>(HybridEncrypt);

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
    const aead = await keysetHandle.getPrimitive<Aead>(Aead, customKeyManager);
    const plaintext = Random.randBytes(20);
    const ciphertext = await aead.encrypt(plaintext);

    // Register another key manager with the custom key type.
    const managerInRegistry = new DummyKeyManager(
        keyTypeUrl, new DummyAead(Random.randBytes(10)), Aead);
    Registry.registerKeyManager(managerInRegistry);

    // Check that the primitive returned by getPrimitive cannot decrypt the
    // ciphertext. This is because managerInRegistry is different from
    // customKeyManager.
    const aeadFromRegistry = await keysetHandle.getPrimitive<Aead>(Aead);
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
        await keysetHandle.getPrimitive<Aead>(Aead, customKeyManager);
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
    const customHybridEncrypt = await keysetHandle.getPrimitive<HybridEncrypt>(
        HybridEncrypt, customKeyManager);
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
    const hybridFromRegistry =
        await keysetHandle.getPrimitive<HybridEncrypt>(HybridEncrypt);
    const ciphertext2 = await hybridFromRegistry.encrypt(plaintext);
    expect(ciphertext2).not.toEqual(ciphertext);

    // Check that the primitive returned by getPrimitive with customKeyManager
    // is the same as customHybridEncrypt.
    const hybridEncryptFromCustomKeyManager =
        await keysetHandle.getPrimitive<HybridEncrypt>(
            HybridEncrypt, customKeyManager);
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
    const hybridEncrypt =
        await publicKeysetHandle.getPrimitive<HybridEncrypt>(HybridEncrypt);
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
        await privateKeysetHandle.getPrimitive<HybridDecrypt>(HybridDecrypt);
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
    const customHybridDecrypt =
        await privateKeysetHandle.getPrimitive<HybridDecrypt>(
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
       const primitive = new DummyMac(new Uint8Array([0xFF]));
       Registry.registerKeyManager(
           new DummyKeyManager(macKeyTypeUrl, primitive, Mac));

       const keysetHandle = new KeysetHandle(keyset);

       try {
         await keysetHandle.getPrimitive<Aead>(Aead);
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
       const primary = assertExists(primitiveSet.getPrimary());
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
    const primary = assertExists(primitiveSet.getPrimary());
    expect(primary.getPrimitive()).toBe(customPrimitive);
  });

  /////////////////////////////////////////////////////////////////////////////
  // tests for readNoSecret method

  it('read no secret, keyset containing secret key material', function() {
    const secretKeyMaterialTypes = [
      PbKeyMaterialType.SYMMETRIC, PbKeyMaterialType.ASYMMETRIC_PRIVATE,
      PbKeyMaterialType.UNKNOWN_KEYMATERIAL
    ];
    for (const secretKeyMaterialType of secretKeyMaterialTypes) {
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
        readNoSecret(reader);
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
    const keysetHandle = readNoSecret(reader);

    expect(keysetHandle.getKeyset()).toEqual(keyset);
  });

  describe('getPublicKeysetHandle', () => {
    it('can get a public keyset from a private keyset', async () => {
      const privateHandle = await generateNew(
          HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
      expect(() => privateHandle.getPublicKeysetHandle())
          .not.toThrowError(
              SecurityException, 'The keyset contains a non-private key');
    });

    it('can not get a public keyset from another public keyset', async () => {
      const privateHandle = await generateNew(
          HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
      const publicHandle = privateHandle.getPublicKeysetHandle();
      expect(() => publicHandle.getPublicKeysetHandle())
          .toThrowError(
              SecurityException, 'The keyset contains a non-private key');
    });
  });

  describe('writeNoSecret', () => {
    it('throws if the keyset contains secret keys', async () => {
      const privateHandle = await generateNew(
          HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
      expect(() => privateHandle.writeNoSecret(new BinaryKeysetWriter()))
          .toThrowError(SecurityException);
    });

    it('writes bytes if the keyset contains no secret keys', async () => {
      const privateHandle = await generateNew(
          HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
      const publicHandle = privateHandle.getPublicKeysetHandle();
      expect(() => publicHandle.writeNoSecret(new BinaryKeysetWriter()))
          .not.toThrow();
    });

    it('can import the keyset using readNoSecret', async () => {
      const privateHandle = await generateNew(
          HybridKeyTemplates.eciesP256HkdfHmacSha256Aes128Gcm());
      const publicHandle = privateHandle.getPublicKeysetHandle();
      const keysetBytes = publicHandle.writeNoSecret(new BinaryKeysetWriter());

      const importedHandle = readNoSecret(new BinaryKeysetReader(keysetBytes));
      expect(publicHandle.getKeyset()).toEqual(importedHandle.getKeyset());
    });
  });
});

/** Function for creating keys for testing purposes. */
function createKey(
    keyId: number, outputPrefix: PbOutputPrefixType, keyTypeUrl: string,
    enabled: boolean,
    opt_keyMaterialType: PbKeyMaterialType =
        PbKeyMaterialType.SYMMETRIC): PbKeysetKey {
  const key = new PbKeysetKey();
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
}

/**
 * Function for creating keysets for testing purposes.
 * Primary has id 1.
 *
 * The function also register DummyKeyManager providing primitives for each
 * keyType added to the Keyset.
 */
function createKeysetAndInitializeRegistry(
    primitiveType: Constructor<unknown>,
    opt_numberOfKeys: number = 15): PbKeyset {
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
    let outputPrefix: PbOutputPrefixType;
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
}

/**
 * @final
 */
class DummyAead extends Aead {
  constructor(private readonly ciphertextSuffix: Uint8Array) {
    super();
  }

  /** @override */
  // Encrypt method just append the primitive identifier to plaintext.
  async encrypt(plaintext: Uint8Array, opt_associatedData?: Uint8Array) {
    const result =
        new Uint8Array(plaintext.length + this.ciphertextSuffix.length);
    result.set(plaintext, 0);
    result.set(this.ciphertextSuffix, plaintext.length);
    return result;
  }

  /** @override */
  // Decrypt method throws an exception whenever ciphertext does not end with
  // ciphertext suffix, otherwise it returns the first part (without
  // ciphertext suffix).
  async decrypt(ciphertext: Uint8Array, opt_associatedData?: Uint8Array) {
    const plaintext = ciphertext.subarray(
        0, ciphertext.length - this.ciphertextSuffix.length);
    const ciphertextSuffix = ciphertext.subarray(
        ciphertext.length - this.ciphertextSuffix.length, ciphertext.length);

    if ([...ciphertextSuffix].toString() !=
        [...this.ciphertextSuffix].toString()) {
      throw new SecurityException('Ciphertext decryption failed.');
    }

    return plaintext;
  }
}

/**
 * @final
 */
class DummyMac extends Mac {
  constructor(private readonly tag: Uint8Array) {
    super();
  }

  /**
   * Just appends the tag to the data.
   * @override
   */
  async computeMac(data: Uint8Array) {
    return this.tag;
  }

  /**
   * Returns whether data ends with tag.
   * @override
   */
  async verifyMac(tag: Uint8Array, data: Uint8Array) {
    return [...tag].toString() === [...this.tag].toString();
  }
}

/** @final */
class DummyHybridEncrypt extends HybridEncrypt {
  constructor(private readonly ciphertextSuffix: Uint8Array) {
    super();
  }
  // Async is used here just because real primitives returns Promise.
  /** @override */
  async encrypt(plaintext: Uint8Array, opt_associatedData?: Uint8Array) {
    return Bytes.concat(plaintext, this.ciphertextSuffix);
  }
}

/** @final */
class DummyHybridDecrypt extends HybridDecrypt {
  constructor(private readonly ciphertextSuffix: Uint8Array) {
    super();
  }
  /** @override */
  async decrypt(ciphertext: Uint8Array, opt_associatedData?: Uint8Array) {
    const cipherLen = ciphertext.length;
    const suffixLen = this.ciphertextSuffix.length;
    const plaintext = ciphertext.subarray(0, cipherLen - suffixLen);
    const suffix = ciphertext.subarray(cipherLen - suffixLen, cipherLen);
    if (!Bytes.isEqual(this.ciphertextSuffix, suffix)) {
      throw new SecurityException('Ciphertext decryption failed.');
    }
    return plaintext;
  }
}

// Key factory and key manager classes used in tests.

/** @final */
class DummyKeyFactory implements KeyManager.KeyFactory {
  /** @override */
  newKey(keyFormat: PbMessage|Uint8Array): PbMessage|Promise<PbMessage> {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  /** @override */
  newKeyData(serializedKeyFormat: Uint8Array): PbKeyData|Promise<PbKeyData> {
    throw new SecurityException('Not implemented, function is not needed.');
  }
}

/**
 * @final
 */
class DummyKeyManager<T> implements KeyManager.KeyManager<T> {
  constructor(
      private readonly keyType: string, private readonly primitive: T,
      private readonly primitiveType: Constructor<T>) {}

  /** @override */
  async getPrimitive(primitiveType: Constructor<T>, key: PbKeyData|PbMessage) {
    if (primitiveType != this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    return this.primitive;
  }

  /** @override */
  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  /** @override */
  getKeyType() {
    return this.keyType;
  }

  /** @override */
  getPrimitiveType() {
    return this.primitiveType;
  }

  /** @override */
  getVersion(): number {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  /** @override */
  getKeyFactory(): KeyManager.KeyFactory {
    throw new SecurityException('Not implemented, function is not needed.');
  }
}
