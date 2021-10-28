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
import {KeyFactory, KeyManager} from './key_manager';
import {generateNew, KeysetHandle, read, readNoSecret} from './keyset_handle';
import {PbKeyData, PbKeyMaterialType, PbKeyset, PbKeysetKey, PbKeyStatusType, PbMessage, PbOutputPrefixType} from './proto';
import * as Registry from './registry';
import {Constructor} from './util';

describe('KeysetHandle', () => {
  beforeEach(() => {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s

    HybridConfig.register();
  });

  afterEach(() => {
    Registry.reset();

    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  describe('constructor', () => {
    it('throws with empty list of keys', async () => {
      const keyset = new PbKeyset().setKeyList([]);
      expect(() => new KeysetHandle(keyset))
          .toThrowError(
              SecurityException,
              'Keyset should be non null and must contain at least one key.');
    });

    it('does not throw for valid keyset protos', async () => {
      const keyset = createKeyset();
      expect(() => new KeysetHandle(keyset)).not.toThrow();
    });
  });

  describe('getKeyset', () => {
    it('returns the underlying keyset proto', async () => {
      const keyset = createKeyset();
      const keysetHandle = new KeysetHandle(keyset);

      const result = keysetHandle.getKeyset();
      expect(result).toEqual(keyset);
    });
  });

  describe('read', () => {
    it('is not yet implemented', async () => {
      const keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
      const keysetHandle = await generateNew(keyTemplate);
      const serializedKeyset =
          CleartextKeysetHandle.serializeToBinary(keysetHandle);
      const keysetReader = new BinaryKeysetReader(serializedKeyset);
      const aead = await keysetHandle.getPrimitive<Aead>(Aead);

      await expectAsync(read(keysetReader, aead))
          .toBeRejectedWithError(
              SecurityException, 'KeysetHandle -- read: Not implemented yet.');
    });
  });

  describe('generateNew', () => {
    it('generates new keyset handles given a key template', async () => {
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
  });

  describe('write', () => {
    it('is not yet implemented', async () => {
      const keyset = createKeysetAndInitializeRegistry(Aead);
      const keysetHandle = new KeysetHandle(keyset);
      const keysetWriter = new BinaryKeysetWriter();
      const aead = await keysetHandle.getPrimitive<Aead>(Aead);

      await expectAsync(keysetHandle.write(keysetWriter, aead))
          .toBeRejectedWithError(
              SecurityException, 'KeysetHandle -- write: Not implemented yet.');
    });
  });

  describe('getPrimitive', () => {
    it('aead', async () => {
      const keyset = createKeysetAndInitializeRegistry(Aead);
      const keysetHandle = new KeysetHandle(keyset);

      const aead = await keysetHandle.getPrimitive<Aead>(Aead);

      // Test the aead primitive returned by getPrimitive method.
      const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6]);
      const ciphertext = await aead.encrypt(plaintext);
      const decryptedText = await aead.decrypt(ciphertext);

      expect(decryptedText).toEqual(plaintext);
    });

    it('hybrid encrypt', async () => {
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

    it('hybrid decrypt', async () => {
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

    it('aead, custom key manager', async () => {
      const keyset = new PbKeyset();

      // Add a new key with a new key type associated to custom key manager
      // to the keyset.
      const keyTypeUrl = 'new_custom_aead_key_type';
      const keyId = 0xFFFFFFFF;
      const key =
          createKey({keyId, outputPrefix: PbOutputPrefixType.TINK, keyTypeUrl});
      keyset.addKey(key);
      keyset.setPrimaryKeyId(keyId);
      const keysetHandle = new KeysetHandle(keyset);

      // Create a custom key manager.
      const customKeyManager = new DummyKeyManager(
          keyTypeUrl, new DummyAead(Random.randBytes(10)), Aead);

      // Encrypt with the primitive returned by customKeyManager.
      const aead =
          await keysetHandle.getPrimitive<Aead>(Aead, customKeyManager);
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

      await expectAsync(aeadFromRegistry.decrypt(ciphertext))
          .toBeRejectedWithError(
              SecurityException, 'Decryption failed for the given ciphertext.');

      // Check that the primitive returned by getPrimitive with customKeyManager
      // decrypts correctly.
      const aeadFromCustomKeyManager =
          await keysetHandle.getPrimitive<Aead>(Aead, customKeyManager);
      const decryptedText = await aeadFromCustomKeyManager.decrypt(ciphertext);
      expect(decryptedText).toEqual(plaintext);
    });

    it('hybrid encrypt, custom key manager', async () => {
      const keyset = new PbKeyset();

      // Add a new key with a new key type associated to custom key manager
      // to the keyset.
      const keyTypeUrl = 'new_custom_hybrid_encrypt_key_type';
      const keyId = 0xFFFFFFFF;
      const key =
          createKey({keyId, outputPrefix: PbOutputPrefixType.TINK, keyTypeUrl});
      keyset.addKey(key);
      keyset.setPrimaryKeyId(keyId);
      const keysetHandle = new KeysetHandle(keyset);

      // Create a custom key manager.
      const customKeyManager = new DummyKeyManager(
          keyTypeUrl, new DummyHybridEncrypt(Random.randBytes(10)),
          HybridEncrypt);

      // Encrypt with the primitive returned by customKeyManager.
      const customHybridEncrypt =
          await keysetHandle.getPrimitive<HybridEncrypt>(
              HybridEncrypt, customKeyManager);
      const plaintext = Random.randBytes(20);
      const ciphertext = await customHybridEncrypt.encrypt(plaintext);

      // Register another key manager with the custom key type.
      const managerInRegistry = new DummyKeyManager(
          keyTypeUrl, new DummyHybridEncrypt(Random.randBytes(10)),
          HybridEncrypt);
      Registry.registerKeyManager(managerInRegistry);

      // Check that the primitive returned by getPrimitive is not the same as
      // customHybridEncrypt. This is because managerInRegistry is different
      // from customKeyManager.
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

    it('hybrid decrypt, custom key manager', async () => {
      // Both private and public keys have the same key id.
      const keyId = 0xFFFFFFFF;

      // Create a public keyset.

      const publicKeyset = new PbKeyset();
      // Add a new key with a new key type associated to custom key manager
      // to the keyset.
      const publicKeyTypeUrl = 'new_custom_hybrid_encrypt_key_type';
      const publicKey = createKey({
        keyId,
        outputPrefix: PbOutputPrefixType.TINK,
        keyTypeUrl: publicKeyTypeUrl
      });
      publicKeyset.addKey(publicKey);
      publicKeyset.setPrimaryKeyId(keyId);
      const publicKeysetHandle = new KeysetHandle(publicKeyset);

      // Create a corresponding private keyset.

      const privateKeyset = new PbKeyset();
      // Add a new key with a new key type associated to custom key manager
      // to the keyset.
      const privateKeyTypeUrl = 'new_custom_hybrid_decrypt_key_type';
      const privateKey = createKey({
        keyId,
        outputPrefix: PbOutputPrefixType.TINK,
        keyTypeUrl: privateKeyTypeUrl
      });
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

      // Check that the primitive returned by getPrimitive cannot decrypt. This
      // is because the ciphertext suffix is different.
      const hybridDecryptFromRegistry =
          await privateKeysetHandle.getPrimitive<HybridDecrypt>(HybridDecrypt);
      await expectAsync(hybridDecryptFromRegistry.decrypt(ciphertext))
          .toBeRejectedWithError(
              SecurityException, 'Decryption failed for the given ciphertext.');

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

    it('keyset contains key corresponding to different primitive', async () => {
      const keyset = createKeysetAndInitializeRegistry(Aead);

      // Add new key with new key type url to the keyset and register a key
      // manager providing Mac primitives with this key.
      const macKeyTypeUrl = 'mac_key_type_1';
      const macKeyId = 0xFFFFFFFF;
      const macKey = createKey({
        keyId: macKeyId,
        outputPrefix: PbOutputPrefixType.TINK,
        keyTypeUrl: macKeyTypeUrl
      });
      keyset.addKey(macKey);
      const primitive = new DummyMac(new Uint8Array([0xFF]));
      Registry.registerKeyManager(
          new DummyKeyManager(macKeyTypeUrl, primitive, Mac));

      const keysetHandle = new KeysetHandle(keyset);

      await expectAsync(keysetHandle.getPrimitive<Aead>(Aead))
          .toBeRejectedWithError(
              SecurityException,
              'Requested primitive type which is not supported by ' +
                  'this key manager.');
    });
  });

  describe('getPrimitiveSet', () => {
    it('primary key is the enabled key with given id', async () => {
      const keyId = 1;
      const primaryUrl = 'key_type_url_for_primary_key';
      const disabledUrl = 'key_type_url_for_disabled_key';

      const keyset = new PbKeyset();
      keyset.addKey(createKey({
        keyId,
        outputPrefix: PbOutputPrefixType.TINK,
        keyTypeUrl: disabledUrl,
        enabled: false
      }));
      keyset.addKey(createKey({
        keyId,
        outputPrefix: PbOutputPrefixType.LEGACY,
        keyTypeUrl: disabledUrl,
        enabled: false
      }));
      keyset.addKey(createKey({
        keyId,
        outputPrefix: PbOutputPrefixType.RAW,
        keyTypeUrl: disabledUrl,
        enabled: false
      }));
      keyset.addKey(createKey({
        keyId,
        outputPrefix: PbOutputPrefixType.TINK,
        keyTypeUrl: primaryUrl,
        enabled: true
      }));
      keyset.setPrimaryKeyId(keyId);

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

    it('disabled keys should be ignored', async () => {
      const enabledRawKeysCount = 10;
      const enabledUrl = 'enabled_key_type_url';
      const disabledUrl = 'disabled_key_type_url';

      // Create keyset with both enabled and disabled RAW keys.
      const keyset = new PbKeyset();
      // Add RAW keys with different ids from [1, ENABLED_RAW_KEYS_COUNT].
      for (let i = 0; i < enabledRawKeysCount; i++) {
        keyset.addKey(createKey({
          keyId: 1 + i,
          outputPrefix: PbOutputPrefixType.RAW,
          keyTypeUrl: enabledUrl,
          enabled: true
        }));
        keyset.addKey(createKey({
          keyId: 1 + i,
          outputPrefix: PbOutputPrefixType.RAW,
          keyTypeUrl: disabledUrl,
          enabled: false
        }));
      }
      keyset.setPrimaryKeyId(1);
      const keysetHandle = new KeysetHandle(keyset);

      // Register KeyManager (the key manager for enabled keys should be
      // enough).
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

    it('with custom key manager', async () => {
      // Create keyset handle.
      const keyTypeUrl = 'some_key_type_url';
      const keyId = 1;
      const key =
          createKey({keyId, outputPrefix: PbOutputPrefixType.TINK, keyTypeUrl});

      const keyset = new PbKeyset();
      keyset.addKey(key);
      keyset.setPrimaryKeyId(keyId);

      const keysetHandle = new KeysetHandle(keyset);

      // Register key manager for the given keyType.
      const primitive = new DummyAead(new Uint8Array(Random.randBytes(10)));
      Registry.registerKeyManager(
          new DummyKeyManager(keyTypeUrl, primitive, Aead));

      // Use getPrimitives with custom key manager for the keyType.
      const customPrimitive =
          new DummyAead(new Uint8Array(Random.randBytes(10)));
      const customKeyManager =
          new DummyKeyManager(keyTypeUrl, customPrimitive, Aead);
      const primitiveSet =
          await keysetHandle.getPrimitiveSet(Aead, customKeyManager);

      // Primary should be the entry corresponding to the keyTypeUrl and thus
      // getPrimitive should return customPrimitive.
      const primary = assertExists(primitiveSet.getPrimary());
      expect(primary.getPrimitive()).toBe(customPrimitive);
    });
  });

  describe('readNoSecret', () => {
    it('throws for keysets containing secret key material', () => {
      const secretKeyMaterialTypes = [
        PbKeyMaterialType.SYMMETRIC, PbKeyMaterialType.ASYMMETRIC_PRIVATE,
        PbKeyMaterialType.UNKNOWN_KEYMATERIAL
      ];
      for (const secretKeyMaterialType of secretKeyMaterialTypes) {
        // Create a public keyset.
        const keyset = new PbKeyset();
        for (let i = 0; i < 3; i++) {
          const key = createKey({
            keyId: i + 1,
            outputPrefix: PbOutputPrefixType.TINK,
            keyTypeUrl: 'someType',
            enabled: (i % 4) < 2,
            keyMaterialType: PbKeyMaterialType.ASYMMETRIC_PUBLIC,
          });
          keyset.addKey(key);
        }
        keyset.setPrimaryKeyId(1);
        const key = createKey({
          keyId: 0xFFFFFFFF,
          outputPrefix: PbOutputPrefixType.RAW,
          keyTypeUrl: 'someType',
          enabled: true,
          keyMaterialType: secretKeyMaterialType,
        });
        keyset.addKey(key);
        const reader =
            BinaryKeysetReader.withUint8Array(keyset.serializeBinary());
        expect(() => readNoSecret(reader))
            .toThrowError(
                SecurityException, 'Keyset contains secret key material.');
      }
    });

    it('returns non-secret keysets', () => {
      // Create a public keyset.
      const keyset = new PbKeyset();
      for (let i = 0; i < 3; i++) {
        const key = createKey({
          keyId: i + 1,
          outputPrefix: PbOutputPrefixType.TINK,
          keyTypeUrl: 'someType',
          enabled: (i % 4) < 2,
          keyMaterialType: PbKeyMaterialType.ASYMMETRIC_PUBLIC,
        });
        keyset.addKey(key);
      }
      keyset.setPrimaryKeyId(1);

      const reader =
          BinaryKeysetReader.withUint8Array(keyset.serializeBinary());
      const keysetHandle = readNoSecret(reader);

      expect(keysetHandle.getKeyset()).toEqual(keyset);
    });
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
function createKey({
  keyId,
  outputPrefix,
  keyTypeUrl,
  enabled = true,
  keyMaterialType = PbKeyMaterialType.SYMMETRIC
}: {
  keyId: number,
  outputPrefix: PbOutputPrefixType,
  keyTypeUrl: string,
  enabled?: boolean,
  keyMaterialType?: PbKeyMaterialType,
}): PbKeysetKey {
  return new PbKeysetKey()
      .setStatus(enabled ? PbKeyStatusType.ENABLED : PbKeyStatusType.DISABLED)
      .setOutputPrefixType(outputPrefix)
      .setKeyId(keyId)
      .setKeyData(new PbKeyData()
                      .setTypeUrl(keyTypeUrl)
                      .setValue(new Uint8Array([1]))
                      .setKeyMaterialType(keyMaterialType));
}

/**
 * Function for creating keysets for testing purposes.
 * Primary has id 1.
 *
 * The function also register DummyKeyManager providing primitives for each
 * keyType added to the Keyset.
 */
function createKeysetAndInitializeRegistry(
    primitiveType: Constructor<unknown>, numberOfKeys = 15): PbKeyset {
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

  for (let i = 1; i < numberOfKeys; i++) {
    const keyTypeUrl = keyTypePrefix + (i % numberOfKeyTypes).toString();
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
    keyset.addKey(
        createKey({keyId: i, outputPrefix, keyTypeUrl, enabled: i % 7 < 6}));
  }

  keyset.setPrimaryKeyId(1);
  return keyset;
}

class DummyAead extends Aead {
  constructor(private readonly ciphertextSuffix: Uint8Array) {
    super();
  }

  /** @override */
  // Encrypt method just append the primitive identifier to plaintext.
  async encrypt(plaintext: Uint8Array, associatedData?: Uint8Array) {
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
  async decrypt(ciphertext: Uint8Array, associatedData?: Uint8Array) {
    const plaintext = ciphertext.subarray(
        0, ciphertext.length - this.ciphertextSuffix.length);
    const ciphertextSuffix = ciphertext.subarray(
        ciphertext.length - this.ciphertextSuffix.length, ciphertext.length);

    if ([...ciphertextSuffix].toString() !==
        [...this.ciphertextSuffix].toString()) {
      throw new SecurityException('Ciphertext decryption failed.');
    }

    return plaintext;
  }
}

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

class DummyHybridEncrypt extends HybridEncrypt {
  constructor(private readonly ciphertextSuffix: Uint8Array) {
    super();
  }
  // Async is used here just because real primitives returns Promise.
  /** @override */
  async encrypt(plaintext: Uint8Array, associatedData?: Uint8Array) {
    return Bytes.concat(plaintext, this.ciphertextSuffix);
  }
}

class DummyHybridDecrypt extends HybridDecrypt {
  constructor(private readonly ciphertextSuffix: Uint8Array) {
    super();
  }

  /** @override */
  async decrypt(ciphertext: Uint8Array, associatedData?: Uint8Array) {
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

class DummyKeyManager<T> implements KeyManager<T> {
  constructor(
      private readonly keyType: string, private readonly primitive: T,
      private readonly primitiveType: Constructor<T>) {}

  async getPrimitive(primitiveType: Constructor<T>, key: PbKeyData|PbMessage) {
    if (primitiveType !== this.getPrimitiveType()) {
      throw new SecurityException(
          'Requested primitive type which is not ' +
          'supported by this key manager.');
    }
    return this.primitive;
  }

  doesSupport(keyType: string) {
    return keyType === this.getKeyType();
  }

  getKeyType() {
    return this.keyType;
  }

  getPrimitiveType() {
    return this.primitiveType;
  }

  getVersion(): number {
    throw new SecurityException('Not implemented, function is not needed.');
  }

  getKeyFactory(): KeyFactory {
    throw new SecurityException('Not implemented, function is not needed.');
  }
}
