/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../aead/aead_config';
import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {PbAesCtrKeyFormat, PbEciesAeadDemParams, PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyData, PbKeyTemplate, PbPointFormat} from '../internal/proto';
import * as Registry from '../internal/registry';
import * as Random from '../subtle/random';
import {assertExists, assertInstanceof} from '../testing/internal/test_utils';

import {EciesAeadHkdfPrivateKeyManager} from './ecies_aead_hkdf_private_key_manager';
import {EciesAeadHkdfPublicKeyManager} from './ecies_aead_hkdf_public_key_manager';
import {HybridDecrypt} from './internal/hybrid_decrypt';
import {HybridEncrypt} from './internal/hybrid_encrypt';

const PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey';
const PRIVATE_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE;
const VERSION = 0;
const PRIVATE_KEY_MANAGER_PRIMITIVE = HybridDecrypt;

const PUBLIC_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
const PUBLIC_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC;
const PUBLIC_KEY_MANAGER_PRIMITIVE = HybridEncrypt;

describe('ecies aead hkdf private key manager test', function() {
  beforeEach(function() {
    AeadConfig.register();
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    Registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('new key, empty key format', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
    }
  });

  it('new key, invalid serialized key format', async function() {
    const invalidSerializedKeyFormat = new Uint8Array(0);
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidSerializedKeyFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
    }
  });

  it('new key, unsupported key format proto', async function() {
    const unsupportedKeyFormatProto = new PbAesCtrKeyFormat();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(unsupportedKeyFormatProto);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyFormat());
    }
  });

  it('new key, invalid format, missing params', async function() {
    const invalidFormat = new PbEciesAeadHkdfKeyFormat();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.invalidKeyFormatMissingParams());
    }
  });

  it('new key, invalid format, invalid params', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();

    // unknown point format
    const invalidFormat = createKeyFormat();
    invalidFormat.getParams()?.setEcPointFormat(PbPointFormat.UNKNOWN_FORMAT);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownPointFormat());
    }
    invalidFormat.getParams()?.setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    invalidFormat.getParams()?.setKemParams(null);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
    }
    invalidFormat.getParams()?.setKemParams(createKemParams());

    // unsupported AEAD template
    const templateTypeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    invalidFormat.getParams()?.getDemParams()?.getAeadDem()?.setTypeUrl(
        templateTypeUrl);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyTemplate(templateTypeUrl));
    }
  });

  it('new key, via key format', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EciesAeadHkdfPrivateKeyManager();
    for (const keyFormat of keyFormats) {
      const key = await manager.getKeyFactory().newKey(keyFormat);

      expect(key.getPublicKey()?.getParams()).toEqual(keyFormat.getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  });

  it('new key data, invalid serialized key format', async function() {
    const serializedKeyFormats = [new Uint8Array(1), new Uint8Array(0)];
    const manager = new EciesAeadHkdfPrivateKeyManager();

    const serializedKeyFormatsLength = serializedKeyFormats.length;
    for (let i = 0; i < serializedKeyFormatsLength; i++) {
      try {
        await manager.getKeyFactory().newKeyData(serializedKeyFormats[i]);
        fail(
            'An exception should be thrown for the string: ' +
            serializedKeyFormats[i]);
      } catch (e: any) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
        continue;
      }
    }
  });

  it('new key data, from valid key format', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EciesAeadHkdfPrivateKeyManager();
    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData =
          await manager.getKeyFactory().newKeyData(serializedKeyFormat);
      expect(keyData.getTypeUrl()).toBe(PRIVATE_KEY_TYPE);
      expect(keyData.getKeyMaterialType()).toBe(PRIVATE_KEY_MATERIAL_TYPE);

      const key =
          PbEciesAeadHkdfPrivateKey.deserializeBinary(keyData.getValue_asU8());
      expect(key.getPublicKey()?.getParams()).toEqual(keyFormat.getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  });

  it('get public key data, invalid private key serialization', function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();

    const privateKey = new Uint8Array([0, 1]);  // not a serialized private key
    try {
      const factory = manager.getKeyFactory();
      factory.getPublicKeyData(privateKey);
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
    }
  });

  it('get public key data, should work', async function() {
    const keyFormat = createKeyFormat();
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const privateKey = await manager.getKeyFactory().newKey(keyFormat);
    const factory = manager.getKeyFactory();
    const publicKeyData =
        factory.getPublicKeyData(privateKey.serializeBinary());

    expect(publicKeyData.getTypeUrl()).toBe(PUBLIC_KEY_TYPE);
    expect(publicKeyData.getKeyMaterialType()).toBe(PUBLIC_KEY_MATERIAL_TYPE);
    const publicKey = PbEciesAeadHkdfPublicKey.deserializeBinary(
        publicKeyData.getValue_asU8());
    expect(publicKey.getVersion())
        .toEqual(assertExists(privateKey.getPublicKey()).getVersion());
    expect(publicKey.getParams())
        .toEqual(assertExists(privateKey.getPublicKey()).getParams());
    expect(publicKey.getX_asU8())
        .toEqual(assertExists(privateKey.getPublicKey()).getX_asU8());
    expect(publicKey.getY_asU8())
        .toEqual(assertExists(privateKey.getPublicKey()).getY_asU8());
  });

  it('get primitive, unsupported key data type', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const keyData =
        (await manager.getKeyFactory().newKeyData(keyFormat.serializeBinary()))
            .setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyType(keyData.getTypeUrl()));
    }
  });

  it('get primitive, unsupported key type', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const key = new PbEciesAeadHkdfPublicKey();

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyType());
    }
  });

  it('get primitive, high version', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const version = manager.getVersion() + 1;
    const keyFormat = createKeyFormat();
    const key = assertInstanceof(
                    await manager.getKeyFactory().newKey(keyFormat),
                    PbEciesAeadHkdfPrivateKey)
                    .setVersion(version);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.versionOutOfBounds());
    }
  });

  it('get primitive, invalid params', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const key = assertInstanceof(
        await manager.getKeyFactory().newKey(keyFormat),
        PbEciesAeadHkdfPrivateKey);

    // missing KEM params
    key.getPublicKey()?.getParams()?.setKemParams(null);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
    }
    key.getPublicKey()?.getParams()?.setKemParams(createKemParams());

    // unsupported AEAD key template type URL
    const templateTypeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    key.getPublicKey()?.getParams()?.getDemParams()?.getAeadDem()?.setTypeUrl(
        templateTypeUrl);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyTemplate(templateTypeUrl));
    }
  });

  it('get primitive, invalid serialized key', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const keyData =
        await manager.getKeyFactory().newKeyData(keyFormat.serializeBinary());


    for (let i = 0; i < 2; ++i) {
      // Set the value of keyData to something which is not a serialization of a
      // proper key.
      keyData.setValue(new Uint8Array(i));
      try {
        await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, keyData);
        fail('An exception should be thrown ' + i.toString());
      } catch (e: any) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
      }
    }
  });

  it('get primitive, from key', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new EciesAeadHkdfPrivateKeyManager();
    const publicKeyManager = new EciesAeadHkdfPublicKeyManager();

    for (const keyFormat of keyFormats) {
      const key = assertInstanceof(
          await privateKeyManager.getKeyFactory().newKey(keyFormat),
          PbEciesAeadHkdfPrivateKey);
      const hybridEncrypt: HybridEncrypt =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, assertExists(key.getPublicKey())));
      const hybridDecrypt: HybridDecrypt =
          assertExists(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, key));

      const plaintext = Random.randBytes(10);
      const ciphertext = await hybridEncrypt.encrypt(plaintext);
      const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });

  it('get primitive, from key data', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new EciesAeadHkdfPrivateKeyManager();
    const publicKeyManager = new EciesAeadHkdfPublicKeyManager();

    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = await privateKeyManager.getKeyFactory().newKeyData(
          serializedKeyFormat);
      const factory = privateKeyManager.getKeyFactory();
      const publicKeyData = factory.getPublicKeyData(keyData.getValue_asU8());
      const hybridEncrypt: HybridEncrypt =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, publicKeyData));
      const hybridDecrypt: HybridDecrypt =
          assertExists(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, keyData));

      const plaintext = Random.randBytes(10);
      const ciphertext = await hybridEncrypt.encrypt(plaintext);
      const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

      expect(decryptedCiphertext).toEqual(plaintext);
    }
  });

  it('does support', function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    expect(manager.doesSupport(PRIVATE_KEY_TYPE)).toBe(true);
  });

  it('get key type', function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    expect(manager.getKeyType()).toBe(PRIVATE_KEY_TYPE);
  });

  it('get primitive type', function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    expect(manager.getPrimitiveType()).toBe(PRIVATE_KEY_MANAGER_PRIMITIVE);
  });

  it('get version', function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    expect(manager.getVersion()).toBe(VERSION);
  });
});

// Helper classes and functions
class ExceptionText {
  static nullKeyFormat(): string {
    return 'SecurityException: Key format has to be non-null.';
  }

  static invalidSerializedKeyFormat(): string {
    return 'SecurityException: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
        ' key format proto.';
  }

  static unsupportedPrimitive(): string {
    return 'SecurityException: Requested primitive type which is not supported by ' +
        'this key manager.';
  }

  static unsupportedKeyFormat(): string {
    return 'SecurityException: Expected ' + PRIVATE_KEY_TYPE +
        ' key format proto.';
  }

  static unsupportedKeyType(opt_requestedKeyType?: string): string {
    const prefix = 'SecurityException: Key type';
    const suffix =
        'is not supported. This key manager supports ' + PRIVATE_KEY_TYPE + '.';
    if (opt_requestedKeyType) {
      return prefix + ' ' + opt_requestedKeyType + ' ' + suffix;
    } else {
      return prefix + ' ' + suffix;
    }
  }

  static versionOutOfBounds(): string {
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  static invalidKeyFormatMissingParams(): string {
    return 'SecurityException: Invalid key format - missing key params.';
  }

  static unknownPointFormat(): string {
    return 'SecurityException: Invalid key params - unknown EC point format.';
  }

  static missingKemParams(): string {
    return 'SecurityException: Invalid params - missing KEM params.';
  }

  static unsupportedKeyTemplate(templateTypeUrl: string): string {
    return 'SecurityException: Invalid DEM params - ' + templateTypeUrl +
        ' template is not supported by ECIES AEAD HKDF.';
  }

  static invalidSerializedKey(): string {
    return 'SecurityException: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
        ' key-proto.';
  }
}

function createKemParams(
    opt_curveType: PbEllipticCurveType = PbEllipticCurveType.NIST_P256,
    opt_hashType: PbHashType = PbHashType.SHA256): PbEciesHkdfKemParams {
  const kemParams = new PbEciesHkdfKemParams()
                        .setCurveType(opt_curveType)
                        .setHkdfHashType(opt_hashType);

  return kemParams;
}

function createDemParams(opt_keyTemplate?: PbKeyTemplate):
    PbEciesAeadDemParams {
  if (!opt_keyTemplate) {
    opt_keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
  }

  const demParams = new PbEciesAeadDemParams().setAeadDem(opt_keyTemplate);

  return demParams;
}

function createKeyParams(
    opt_curveType?: PbEllipticCurveType, opt_hashType?: PbHashType,
    opt_keyTemplate?: PbKeyTemplate,
    opt_pointFormat: PbPointFormat =
        PbPointFormat.UNCOMPRESSED): PbEciesAeadHkdfParams {
  const params = new PbEciesAeadHkdfParams()
                     .setKemParams(createKemParams(opt_curveType, opt_hashType))
                     .setDemParams(createDemParams(opt_keyTemplate))
                     .setEcPointFormat(opt_pointFormat);

  return params;
}

function createKeyFormat(
    opt_curveType?: PbEllipticCurveType, opt_hashType?: PbHashType,
    opt_keyTemplate?: PbKeyTemplate,
    opt_pointFormat?: PbPointFormat): PbEciesAeadHkdfKeyFormat {
  const keyFormat = new PbEciesAeadHkdfKeyFormat().setParams(createKeyParams(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));
  return keyFormat;
}

/**
 * Create set of key formats with all possible predefined/supported parameters.
 */
function createTestSetOfKeyFormats(): PbEciesAeadHkdfKeyFormat[] {
  const curveTypes = [
    PbEllipticCurveType.NIST_P256, PbEllipticCurveType.NIST_P384,
    PbEllipticCurveType.NIST_P521
  ];
  const hashTypes = [PbHashType.SHA1, PbHashType.SHA256, PbHashType.SHA512];
  const keyTemplates = [
    AeadKeyTemplates.aes128CtrHmacSha256(),
    AeadKeyTemplates.aes256CtrHmacSha256()
  ];
  const pointFormats = [PbPointFormat.UNCOMPRESSED];
  const keyFormats: PbEciesAeadHkdfKeyFormat[] = [];
  for (const curve of curveTypes) {
    for (const hkdfHash of hashTypes) {
      for (const keyTemplate of keyTemplates) {
        for (const pointFormat of pointFormats) {
          const keyFormat =
              createKeyFormat(curve, hkdfHash, keyTemplate, pointFormat);
          keyFormats.push(keyFormat);
        }
      }
    }
  }
  return keyFormats;
}
