/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../../../aead/aead_config';
import {SecurityException} from '../../../exception/security_exception';
import {PbEciesAeadHkdfPublicKey, PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeKeyFormat, PbHpkeParams, PbHpkePublicKey, PbKeyData} from '../../../internal/proto';
import * as registry from '../../../internal/registry';
import * as random from '../../../subtle/random';
import {assertExists} from '../../../testing/internal/test_utils';
import {HybridEncrypt} from '../../internal/hybrid_encrypt';

import {HpkePrivateKeyManager} from './hpke_private_key_manager';
import {HpkePublicKeyManager} from './hpke_public_key_manager';

const KEY_TYPE = 'type.googleapis.com/google.crypto.tink.HpkePublicKey';
const VERSION = 0;
const PRIMITIVE = HybridEncrypt;

function createValidParams() {
  return new PbHpkeParams()
      .setKem(PbHpkeKem.DHKEM_P256_HKDF_SHA256)
      .setKdf(PbHpkeKdf.HKDF_SHA256)
      .setAead(PbHpkeAead.AES_128_GCM);
}

async function createPublicKey(params: PbHpkeParams = createValidParams()):
    Promise<PbHpkePublicKey> {
  const privateManager = new HpkePrivateKeyManager();
  const privateKey = await privateManager.getKeyFactory().newKey(
      new PbHpkeKeyFormat().setParams(params));
  return privateKey.getPublicKey()!;
}

/** Creates a set of keys with all possible predefined/supported parameters. */
async function createTestSetOfKeys(): Promise<PbHpkePublicKey[]> {
  const kemTypes =
      [PbHpkeKem.DHKEM_P256_HKDF_SHA256, PbHpkeKem.DHKEM_P521_HKDF_SHA512];
  const kdfTypes = [PbHpkeKdf.HKDF_SHA256, PbHpkeKdf.HKDF_SHA512];
  const aeadTypes = [PbHpkeAead.AES_128_GCM, PbHpkeAead.AES_256_GCM];

  const keys: PbHpkePublicKey[] = [];
  for (const kem of kemTypes) {
    for (const kdf of kdfTypes) {
      for (const aead of aeadTypes) {
        const params = new PbHpkeParams().setKem(kem).setKdf(kdf).setAead(aead);
        const key = await createPublicKey(params);
        keys.push(key);
      }
    }
  }
  return keys;
}

async function createKeyData() {
  const key = await createPublicKey();
  return new PbKeyData()
      .setTypeUrl(KEY_TYPE)
      .setValue(key.serializeBinary())
      .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
}

describe('HpkePublicKeyManagerTest', () => {
  beforeEach(() => {
    AeadConfig.register();
    /** Use a generous promise timeout for running continuously. */
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(() => {
    registry.reset();
    /** Reset the promise timeout to default value. */
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  const manager = new HpkePublicKeyManager();

  it('new key', () => {
    try {
      manager.getKeyFactory().newKey(
          new PbHpkeKeyFormat().setParams(createValidParams()));
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'This operation is not supported for public keys. ' +
              'Use HpkePrivateKeyManager to generate new keys.');
    }
  });

  it('new key data', () => {
    try {
      manager.getKeyFactory().newKeyData(new PbHpkeKeyFormat()
                                             .setParams(createValidParams())
                                             .serializeBinary());
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'This operation is not supported for public keys. ' +
              'Use HpkePrivateKeyManager to generate new keys.');
    }
  });

  it('get primitive, unsupported key data type', async () => {
    const keyData: PbKeyData =
        (await createKeyData()).setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Key type unsupported_key_type_url is not supported. This key manager supports ' +
              KEY_TYPE + '.');
    }
  });

  it('get primitive, unsupported key type', async () => {
    const key = new PbEciesAeadHkdfPublicKey();

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe(
              'Key type is not supported. This key manager supports ' +
              KEY_TYPE + '.');
    }
  });

  it('get primitive, high version', async () => {
    const version = 1;
    const key: PbHpkePublicKey = (await createPublicKey()).setVersion(version);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Version is out of bound, must be between 0 and 0.');
    }
  });

  it('get primitive, missing params', async () => {
    const key: PbHpkePublicKey = (await createPublicKey()).setParams(null);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid public key - missing key params.');
    }
  });

  it('get primitive, invalid params', async () => {
    const key: PbHpkePublicKey = await createPublicKey();

    key.getParams()?.setKem(PbHpkeKem.KEM_UNKNOWN);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid hpke params - unknown KEM identifier.');
    }
  });

  it('get primitive, invalid key', async () => {
    const key: PbHpkePublicKey = (await createPublicKey()).setPublicKey('');

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: unknown) {
      expect((e as SecurityException).message)
          .toBe('Invalid public key - missing public key value.');
    }
  });

  it('get primitive, invalid serialized key', async () => {
    const keyData: PbKeyData = await createKeyData();

    for (let i = 1; i < 3; ++i) {
      /**
       * Set the value of keyData to something which is not a serialization of
       * a proper key.
       */
      keyData.setValue(new Uint8Array(i));
      try {
        await manager.getPrimitive(PRIMITIVE, keyData);
        fail('An exception should be thrown ' + i.toString());
      } catch (e: unknown) {
        expect((e as SecurityException).message)
            .toBe('Input cannot be parsed as ' + KEY_TYPE + ' key-proto.');
      }
    }
  });

  /** Tests for getting primitive from valid key/keyData. */
  it('get primitive, from key', async () => {
    const keys: PbHpkePublicKey[] = await createTestSetOfKeys();
    for (const key of keys) {
      const primitive: HybridEncrypt =
          assertExists(await manager.getPrimitive(PRIMITIVE, key));

      const plaintext = random.randBytes(10);
      const ciphertext = await primitive.encrypt(plaintext);

      expect(ciphertext).not.toEqual(plaintext);
    }
  });

  it('get primitive, from key data', async () => {
    const keys: PbHpkePublicKey[] = await createTestSetOfKeys();

    for (const key of keys) {
      const keyData =
          new PbKeyData()
              .setTypeUrl(KEY_TYPE)
              .setValue(key.serializeBinary())
              .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);
      const primitive: HybridEncrypt =
          assertExists(await manager.getPrimitive(PRIMITIVE, keyData));

      const plaintext = random.randBytes(10);
      const ciphertext = await primitive.encrypt(plaintext);

      expect(ciphertext).not.toEqual(plaintext);
    }
  });

  it('does support', () => {
    expect(manager.doesSupport(KEY_TYPE)).toBe(true);
  });

  it('does support fails for different key type', () => {
    expect(manager.doesSupport(
               'type.googleapis.com/google.crypto.tink.HpkePrivateKey'))
        .toBe(false);
  });

  it('get key type', () => {
    expect(manager.getKeyType()).toBe(KEY_TYPE);
  });

  it('get primitive type', () => {
    expect(manager.getPrimitiveType()).toBe(PRIMITIVE);
  });

  it('get version', () => {
    expect(manager.getVersion()).toBe(VERSION);
  });
});
