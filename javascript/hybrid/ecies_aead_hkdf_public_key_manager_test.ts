/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../aead/aead_config';
import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {PbAesCtrKey, PbEciesAeadDemParams, PbEciesAeadHkdfParams, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyData, PbKeyTemplate, PbPointFormat} from '../internal/proto';
import * as Registry from '../internal/registry';
import * as Util from '../internal/util';
import * as Bytes from '../subtle/bytes';
import * as EllipticCurves from '../subtle/elliptic_curves';
import * as Random from '../subtle/random';
import {assertExists} from '../testing/internal/test_utils';

import {EciesAeadHkdfPublicKeyManager} from './ecies_aead_hkdf_public_key_manager';
import {HybridEncrypt} from './internal/hybrid_encrypt';

const KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
const VERSION = 0;
const PRIMITIVE = HybridEncrypt;

describe('ecies aead hkdf public key manager test', function() {
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

  it('new key', function() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    try {
      manager.getKeyFactory().newKey(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.notSupported());
    }
  });

  it('new key data', function() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    try {
      manager.getKeyFactory().newKeyData(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.notSupported());
    }
  });

  it('get primitive, unsupported key data type', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keyData =
        (await createKeyData()).setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyType(keyData.getTypeUrl()));
    }
  });

  it('get primitive, unsupported key type', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = new PbAesCtrKey();

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyType());
    }
  });

  it('get primitive, high version', async function() {
    const version = 1;
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = (await createKey()).setVersion(version);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.versionOutOfBounds());
    }
  });

  it('get primitive, missing params', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = (await createKey()).setParams(null);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingParams());
    }
  });

  it('get primitive, invalid params', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = await createKey();

    // unknown point format
    key.getParams()?.setEcPointFormat(PbPointFormat.UNKNOWN_FORMAT);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownPointFormat());
    }
    key.getParams()?.setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    key.getParams()?.setKemParams(null);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
    }
    key.getParams()?.setKemParams(createKemParams());

    // unsupported AEAD key template
    const typeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    key.getParams()?.getDemParams()?.getAeadDem()?.setTypeUrl(typeUrl);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyTemplate(typeUrl));
    }
  });

  it('get primitive, invalid key', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = (await createKey()).setX('');

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingXY());
    }
    key.getParams()?.setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    key.getParams()?.setKemParams(null);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
    }
    key.getParams()?.setKemParams(createKemParams());

    // unsupported AEAD key template
    const typeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    key.getParams()?.getDemParams()?.getAeadDem()?.setTypeUrl(typeUrl);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyTemplate(typeUrl));
    }
  });

  it('get primitive, invalid serialized key', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keyData = await createKeyData();

    for (let i = 0; i < 2; ++i) {
      // Set the value of keyData to something which is not a serialization of a
      // proper key.
      keyData.setValue(new Uint8Array(i));
      try {
        await manager.getPrimitive(PRIMITIVE, keyData);
        fail('An exception should be thrown ' + i.toString());
      } catch (e: any) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
      }
    }
  });

  // tests for getting primitive from valid key/keyData
  it('get primitive, from key', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keys = await createTestSetOfKeys();
    for (const key of keys) {
      const primitive: HybridEncrypt =
          assertExists(await manager.getPrimitive(PRIMITIVE, key));

      const plaintext = Random.randBytes(10);
      const ciphertext = await primitive.encrypt(plaintext);

      expect(ciphertext).not.toEqual(plaintext);
    }
  });

  it('get primitive, from key data', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keyDatas = await createTestSetOfKeyDatas();

    for (const key of keyDatas) {
      const primitive: HybridEncrypt =
          assertExists(await manager.getPrimitive(PRIMITIVE, key));

      const plaintext = Random.randBytes(10);
      const ciphertext = await primitive.encrypt(plaintext);

      expect(ciphertext).not.toEqual(plaintext);
    }
  });

  it('does support', function() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    expect(manager.doesSupport(KEY_TYPE)).toBe(true);
  });

  it('get key type', function() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    expect(manager.getKeyType()).toBe(KEY_TYPE);
  });

  it('get primitive type', function() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    expect(manager.getPrimitiveType()).toBe(PRIMITIVE);
  });

  it('get version', function() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    expect(manager.getVersion()).toBe(VERSION);
  });
});

// Helper classes and functions
class ExceptionText {
  static notSupported(): string {
    return 'SecurityException: This operation is not supported for public keys. ' +
        'Use EciesAeadHkdfPrivateKeyManager to generate new keys.';
  }

  static unsupportedPrimitive(): string {
    return 'SecurityException: Requested primitive type which is not supported by ' +
        'this key manager.';
  }

  static unsupportedKeyType(opt_requestedKeyType?: string): string {
    const prefix = 'SecurityException: Key type';
    const suffix =
        'is not supported. This key manager supports ' + KEY_TYPE + '.';
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

  static missingParams(): string {
    return 'SecurityException: Invalid public key - missing key params.';
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

  static missingXY(): string {
    return 'SecurityException: Invalid public key - missing value of X or Y.';
  }

  static invalidSerializedKey(): string {
    return 'SecurityException: Input cannot be parsed as ' + KEY_TYPE +
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

async function createKey(
    opt_curveType: PbEllipticCurveType = PbEllipticCurveType.NIST_P256,
    opt_hashType?: PbHashType, opt_keyTemplate?: PbKeyTemplate,
    opt_pointFormat?: PbPointFormat): Promise<PbEciesAeadHkdfPublicKey> {
  const curveSubtleType = Util.curveTypeProtoToSubtle(opt_curveType);
  const curveName = EllipticCurves.curveToString(curveSubtleType);

  const key =
      new PbEciesAeadHkdfPublicKey().setVersion(0).setParams(createKeyParams(
          opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));


  const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
  const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
  key.setX(
      Bytes.fromBase64(assertExists(publicKey['x']), /* opt_webSafe = */ true));
  key.setY(
      Bytes.fromBase64(assertExists(publicKey['y']), /* opt_webSafe = */ true));

  return key;
}

function createKeyDataFromKey(key: PbEciesAeadHkdfPublicKey): PbKeyData {
  const keyData =
      new PbKeyData()
          .setTypeUrl(KEY_TYPE)
          .setValue(key.serializeBinary())
          .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);

  return keyData;
}

async function createKeyData(
    opt_curveType?: PbEllipticCurveType, opt_hashType?: PbHashType,
    opt_keyTemplate?: PbKeyTemplate,
    opt_pointFormat?: PbPointFormat): Promise<PbKeyData> {
  const key = await createKey(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat);
  return createKeyDataFromKey(key);
}

/** Create set of keys with all possible predefined/supported parameters. */
async function createTestSetOfKeys(): Promise<PbEciesAeadHkdfPublicKey[]> {
  const curveTypes = [
    PbEllipticCurveType.NIST_P256, PbEllipticCurveType.NIST_P384,
    PbEllipticCurveType.NIST_P521
  ];
  const hashTypes = [PbHashType.SHA1, PbHashType.SHA256, PbHashType.SHA512];
  const keyTemplates =
      [AeadKeyTemplates.aes128CtrHmacSha256(), AeadKeyTemplates.aes256Gcm()];
  const pointFormats = [PbPointFormat.UNCOMPRESSED];

  const keys: PbEciesAeadHkdfPublicKey[] = [];
  for (const curve of curveTypes) {
    for (const hkdfHash of hashTypes) {
      for (const keyTemplate of keyTemplates) {
        for (const pointFormat of pointFormats) {
          const key =
              await createKey(curve, hkdfHash, keyTemplate, pointFormat);
          keys.push(key);
        }
      }
    }
  }
  return keys;
}

/**
 * Create set of keyData protos with keys of all possible predefined/supported
 * parameters.
 */
async function createTestSetOfKeyDatas(): Promise<PbKeyData[]> {
  const keys = await createTestSetOfKeys();

  const keyDatas: PbKeyData[] = [];
  for (const key of keys) {
    const keyData = await createKeyDataFromKey(key);
    keyDatas.push(keyData);
  }

  return keyDatas;
}
