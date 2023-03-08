/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../../../aead/aead_config';
import {SecurityException} from '../../../exception/security_exception';
import {PbEciesAeadHkdfKeyFormat, PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeKeyFormat, PbHpkeParams, PbHpkePrivateKey, PbHpkePublicKey, PbKeyData} from '../../../internal/proto';
import {bytesAsU8} from '../../../internal/proto_shims';
import * as registry from '../../../internal/registry';
import * as random from '../../../subtle/random';
import {assertExists, assertInstanceof, assertMessageEquals} from '../../../testing/internal/test_utils';
import {HybridDecrypt} from '../../internal/hybrid_decrypt';
import {HybridEncrypt} from '../../internal/hybrid_encrypt';

import {HpkePrivateKeyManager} from './hpke_private_key_manager';
import {HpkePublicKeyManager} from './hpke_public_key_manager';

const PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.HpkePrivateKey';
const PRIVATE_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE;
const VERSION = 0;
const PRIVATE_KEY_MANAGER_PRIMITIVE = HybridDecrypt;

const PUBLIC_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.HpkePublicKey';
const PUBLIC_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC;
const PUBLIC_KEY_MANAGER_PRIMITIVE = HybridEncrypt;

function createValidParams() {
  return new PbHpkeParams()
      .setKem(PbHpkeKem.DHKEM_P256_HKDF_SHA256)
      .setKdf(PbHpkeKdf.HKDF_SHA256)
      .setAead(PbHpkeAead.AES_128_GCM);
}

/**
 * Creates a set of key formats with all possible predefined/supported
 * parameters.
 */
function createTestSetOfKeyFormats(): PbHpkeKeyFormat[] {
  const kemTypes =
      [PbHpkeKem.DHKEM_P256_HKDF_SHA256, PbHpkeKem.DHKEM_P521_HKDF_SHA512];
  const kdfTypes = [PbHpkeKdf.HKDF_SHA256, PbHpkeKdf.HKDF_SHA512];
  const aeadTypes = [PbHpkeAead.AES_128_GCM, PbHpkeAead.AES_256_GCM];

  const keyFormats: PbHpkeKeyFormat[] = [];
  for (const kem of kemTypes) {
    for (const kdf of kdfTypes) {
      for (const aead of aeadTypes) {
        const params = new PbHpkeParams().setKem(kem).setKdf(kdf).setAead(aead);
        const keyFormat = new PbHpkeKeyFormat().setParams(params);
        keyFormats.push(keyFormat);
      }
    }
  }
  return keyFormats;
}

describe('HpkePrivateKeyManagerTest', () => {
  beforeEach(() => {
    AeadConfig.register();
    /** Use a generous promise timeout for running continuously */
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(() => {
    registry.reset();
    /** Reset the promise timeout to default value. */
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });
  const manager = new HpkePrivateKeyManager();

  it('new key, empty key format', async () => {
    try {
      await manager.getKeyFactory().newKey(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
              ' key format proto.');
    }
  });

  it('new key, unsupported key format proto', async () => {
    const unsupportedKeyFormatProto = new PbEciesAeadHkdfKeyFormat();
    try {
      await manager.getKeyFactory().newKey(unsupportedKeyFormatProto);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Expected ' + PRIVATE_KEY_TYPE + ' key format proto.');
    }
  });

  it('new key, invalid format, missing params', async () => {
    const invalidFormat = new PbHpkeKeyFormat();

    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid key format - missing key params.');
    }
  });

  it('new key, invalid format, invalid params', async () => {
    // Create invalid params with unknown kem.
    const invalidParams = createValidParams().setKem(PbHpkeKem.KEM_UNKNOWN);
    const invalidFormat = new PbHpkeKeyFormat().setParams(invalidParams);

    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid hpke params - unknown KEM identifier.');
    }
  });

  it('new key, via key format should work', async () => {
    const keyFormats = createTestSetOfKeyFormats();
    for (const keyFormat of keyFormats) {
      const key = await manager.getKeyFactory().newKey(keyFormat);

      expect(key.getPublicKey()?.getParams()).toEqual(keyFormat.getParams());
    }
  });

  it('new key data, invalid serialized key format', async () => {
    const serializedKeyFormats = [new Uint8Array(1), new Uint8Array(2)];
    const serializedKeyFormatsLength = serializedKeyFormats.length;
    for (let i = 0; i < serializedKeyFormatsLength; i++) {
      try {
        await manager.getKeyFactory().newKeyData(serializedKeyFormats[i]);
        fail('An exception should be thrown.');
      } catch (e: unknown) {
        expect((e as SecurityException).message)
            .toBe(
                'Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
                ' key format proto.');
      }
    }
  });

  it('new key data, from valid key format', async () => {
    const keyFormats = createTestSetOfKeyFormats();
    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData =
          await manager.getKeyFactory().newKeyData(serializedKeyFormat);
      expect(keyData.getTypeUrl()).toBe(PRIVATE_KEY_TYPE);
      expect(keyData.getKeyMaterialType()).toBe(PRIVATE_KEY_MATERIAL_TYPE);

      const key = PbHpkePrivateKey.deserializeBinary(keyData.getValue());
      assertMessageEquals(
          key.getPublicKey()?.getParams()!, keyFormat.getParams()!);
    }
  });

  it('get public key data, invalid private key serialization', () => {
    const invalidPrivateKeySerialization = new Uint8Array([0, 1]);
    try {
      manager.getKeyFactory().getPublicKeyData(invalidPrivateKeySerialization);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Input cannot be parsed as ' + PRIVATE_KEY_TYPE + ' key-proto.');
    }
  });

  it('get public key data, should work', async () => {
    const keyFormat = new PbHpkeKeyFormat().setParams(createValidParams());
    const privateKey = await manager.getKeyFactory().newKey(keyFormat);
    const factory = manager.getKeyFactory();
    const publicKeyData =
        factory.getPublicKeyData(privateKey.serializeBinary());

    expect(publicKeyData.getTypeUrl()).toBe(PUBLIC_KEY_TYPE);
    expect(publicKeyData.getKeyMaterialType()).toBe(PUBLIC_KEY_MATERIAL_TYPE);
    const publicKey =
        PbHpkePublicKey.deserializeBinary(publicKeyData.getValue());
    expect(publicKey.getVersion())
        .toEqual(assertExists(privateKey.getPublicKey()).getVersion());
    assertMessageEquals(
        publicKey.getParams()!,
        assertExists(privateKey.getPublicKey()).getParams()!);
    expect(bytesAsU8(publicKey.getPublicKey()))
        .toEqual(
            bytesAsU8(assertExists(privateKey.getPublicKey()).getPublicKey()));
  });

  it('get primitive, unsupported key data type', async () => {
    const keyFormat = new PbHpkeKeyFormat().setParams(createValidParams());
    const keyData =
        (await manager.getKeyFactory().newKeyData(keyFormat.serializeBinary()))
            .setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Key type unsupported_key_type_url is not supported. This key manager supports ' +
              PRIVATE_KEY_TYPE + '.');
    }
  });

  it('get primitive, unsupported key type', async () => {
    const key = new PbHpkePublicKey();
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Key type is not supported. This key manager supports ' +
              PRIVATE_KEY_TYPE + '.');
    }
  });

  it('get primitive, high version', async () => {
    const version = manager.getVersion() + 1;
    const keyFormat = new PbHpkeKeyFormat().setParams(createValidParams());
    const key =
        assertInstanceof(
            await manager.getKeyFactory().newKey(keyFormat), PbHpkePrivateKey)
            .setVersion(version);

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Version is out of bound, must be between 0 and 0.');
    }
  });

  it('get primitive, invalid params', async () => {
    const keyFormat = new PbHpkeKeyFormat().setParams(createValidParams());
    const key = assertInstanceof(
        await manager.getKeyFactory().newKey(keyFormat), PbHpkePrivateKey);

    key.getPublicKey()?.getParams()?.setKem(PbHpkeKem.KEM_UNKNOWN);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid hpke params - unknown KEM identifier.');
    }
  });

  it('get primitive, invalid serialized key', async () => {
    const keyFormat = new PbHpkeKeyFormat().setParams(createValidParams());
    const keyData =
        await manager.getKeyFactory().newKeyData(keyFormat.serializeBinary());

    for (let i = 1; i < 3; ++i) {
      /**
       * Set the value of keyData to something which is not a serialization of
       * a proper key.
       */
      keyData.setValue(new Uint8Array(i));
      try {
        await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, keyData);
        fail('An exception should be thrown ' + i.toString());
      } catch (e: unknown) {
        expect((e as SecurityException).message)
            .toBe(
                'Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
                ' key-proto.');
      }
    }
  });

  it('get primitive, from key', async () => {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new HpkePrivateKeyManager();
    const publicKeyManager = new HpkePublicKeyManager();

    for (const keyFormat of keyFormats) {
      const key = assertInstanceof(
          await privateKeyManager.getKeyFactory().newKey(keyFormat),
          PbHpkePrivateKey);
      const hybridEncrypt: HybridEncrypt =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, assertExists(key.getPublicKey())));
      const hybridDecrypt: HybridDecrypt =
          assertExists(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, key));

      const plaintext = random.randBytes(10);
      const ciphertext = await hybridEncrypt.encrypt(plaintext);
      const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });

  it('get primitive, from key data', async () => {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new HpkePrivateKeyManager();
    const publicKeyManager = new HpkePublicKeyManager();

    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = await privateKeyManager.getKeyFactory().newKeyData(
          serializedKeyFormat);
      const factory = privateKeyManager.getKeyFactory();
      const publicKeyData =
          factory.getPublicKeyData(bytesAsU8(keyData.getValue()));
      const hybridEncrypt: HybridEncrypt =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, publicKeyData));
      const hybridDecrypt: HybridDecrypt =
          assertExists(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, keyData));

      const plaintext = random.randBytes(10);
      const ciphertext = await hybridEncrypt.encrypt(plaintext);
      const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });

  it('does support', () => {
    expect(manager.doesSupport(PRIVATE_KEY_TYPE)).toBe(true);
  });

  it('does support fails for different key type', () => {
    expect(manager.doesSupport(
               'type.googleapis.com/google.crypto.tink.HpkePublicKey'))
        .toBe(false);
  });

  it('get key type', () => {
    expect(manager.getKeyType()).toBe(PRIVATE_KEY_TYPE);
  });

  it('get primitive type', () => {
    expect(manager.getPrimitiveType()).toBe(PRIVATE_KEY_MANAGER_PRIMITIVE);
  });

  it('get version', () => {
    expect(manager.getVersion()).toBe(VERSION);
  });
});
