/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbEcdsaParams, PbEcdsaPublicKey, PbEcdsaSignatureEncoding, PbEllipticCurveType, PbHashType, PbKeyData} from '../internal/proto';
import * as Registry from '../internal/registry';
import * as Util from '../internal/util';
import * as Bytes from '../subtle/bytes';
import * as EllipticCurves from '../subtle/elliptic_curves';
import {assertExists} from '../testing/internal/test_utils';

import {EcdsaPublicKeyManager} from './ecdsa_public_key_manager';
import {PublicKeyVerify} from './internal/public_key_verify';

const KEY_TYPE = 'type.googleapis.com/google.crypto.tink.EcdsaPublicKey';
const VERSION = 0;
const PRIMITIVE = PublicKeyVerify;

describe('ecdsa public key manager test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    Registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('new key', function() {
    const manager = new EcdsaPublicKeyManager();

    try {
      manager.getKeyFactory().newKey(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.notSupported());
    }
  });

  it('new key data', function() {
    const manager = new EcdsaPublicKeyManager();

    try {
      manager.getKeyFactory().newKeyData(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.notSupported());
    }
  });

  it('get primitive, unsupported key data type', async function() {
    const manager = new EcdsaPublicKeyManager();
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
    const manager = new EcdsaPublicKeyManager();
    const key = new PbEcdsaParams();
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyType());
    }
  });

  it('get primitive, high version', async function() {
    const version = 1;
    const manager = new EcdsaPublicKeyManager();
    const key = (await createKey()).setVersion(version);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.versionOutOfBounds());
    }
  });

  it('get primitive, missing params', async function() {
    const manager = new EcdsaPublicKeyManager();
    const key = (await createKey()).setParams(null);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingParams());
    }
  });

  it('get primitive, invalid params', async function() {
    const manager = new EcdsaPublicKeyManager();
    const key = await createKey();

    // Unknown encoding.
    key.getParams()?.setEncoding(PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownEncoding());
    }
    key.getParams()?.setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    key.getParams()?.setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownHash());
    }
    key.getParams()?.setHashType(PbHashType.SHA256);

    // Unknown curve.
    key.getParams()?.setCurve(PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownCurve());
    }

    // Bad hash + curve combinations.
    key.getParams()?.setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256');
    }
    key.getParams()?.setCurve(PbEllipticCurveType.NIST_P521);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-512 (because curve is P-521) but got SHA-256');
    }
  });

  it('get primitive, invalid key', async function() {
    const manager = new EcdsaPublicKeyManager();
    const key = await createKey();
    const x = key.getX_asU8();
    key.setX(new Uint8Array([0]));

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(ExceptionText.webCryptoErrors()).toContain(e.toString());
    }

    key.setX(x);
    key.setY(new Uint8Array([0]));
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(ExceptionText.webCryptoErrors()).toContain(e.toString());
    }
  });

  it('get primitive, invalid serialized key', async function() {
    const manager = new EcdsaPublicKeyManager();
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
    const manager = new EcdsaPublicKeyManager();
    const keys = await createTestSetOfKeys();
    for (const key of keys) {
      await manager.getPrimitive(PRIMITIVE, key);
    }
  });

  it('get primitive, from key data', async function() {
    const manager = new EcdsaPublicKeyManager();
    const keyDatas = await createTestSetOfKeyDatas();
    for (const key of keyDatas) {
      await manager.getPrimitive(PRIMITIVE, key);
    }
  });

  it('does support', function() {
    const manager = new EcdsaPublicKeyManager();

    expect(manager.doesSupport(KEY_TYPE)).toBe(true);
  });

  it('get key type', function() {
    const manager = new EcdsaPublicKeyManager();

    expect(manager.getKeyType()).toBe(KEY_TYPE);
  });

  it('get primitive type', function() {
    const manager = new EcdsaPublicKeyManager();

    expect(manager.getPrimitiveType()).toBe(PRIMITIVE);
  });

  it('get version', function() {
    const manager = new EcdsaPublicKeyManager();
    expect(manager.getVersion()).toBe(VERSION);
  });
});

// Helper classes and functions
class ExceptionText {
  static notSupported(): string {
    return 'SecurityException: This operation is not supported for public keys. ' +
        'Use EcdsaPrivateKeyManager to generate new keys.';
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

  static unknownEncoding(): string {
    return 'SecurityException: Invalid public key - missing signature encoding.';
  }

  static unknownHash(): string {
    return 'SecurityException: Unknown hash type.';
  }

  static unknownCurve(): string {
    return 'SecurityException: Unknown curve type.';
  }

  static missingParams(): string {
    return 'SecurityException: Invalid public key - missing params.';
  }

  static missingXY(): string {
    return 'SecurityException: Invalid public key - missing value of X or Y.';
  }

  static invalidSerializedKey(): string {
    return 'SecurityException: Input cannot be parsed as ' + KEY_TYPE +
        ' key-proto.';
  }

  static webCryptoErrors(): string[] {
    return [
      'DataError',
      // Firefox
      'DataError: Data provided to an operation does not meet requirements',
    ];
  }
}

function createParams(
    curveType: PbEllipticCurveType, hashType: PbHashType,
    encoding: PbEcdsaSignatureEncoding): PbEcdsaParams {
  const params = (new PbEcdsaParams())
                     .setCurve(curveType)
                     .setHashType(hashType)
                     .setEncoding(encoding);
  return params;
}

async function createKey(
    opt_curveType: PbEllipticCurveType = PbEllipticCurveType.NIST_P256,
    opt_hashType: PbHashType = PbHashType.SHA256,
    opt_encoding: PbEcdsaSignatureEncoding =
        PbEcdsaSignatureEncoding.DER): Promise<PbEcdsaPublicKey> {
  const curveSubtleType = Util.curveTypeProtoToSubtle(opt_curveType);
  const curveName = EllipticCurves.curveToString(curveSubtleType);
  const key =
      (new PbEcdsaPublicKey())
          .setVersion(0)
          .setParams(createParams(opt_curveType, opt_hashType, opt_encoding));
  const keyPair = await EllipticCurves.generateKeyPair('ECDSA', curveName);
  const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
  key.setX(
      Bytes.fromBase64(assertExists(publicKey['x']), /* opt_webSafe = */ true));
  key.setY(
      Bytes.fromBase64(assertExists(publicKey['y']), /* opt_webSafe = */ true));
  return key;
}

function createKeyDataFromKey(key: PbEcdsaPublicKey): PbKeyData {
  const keyData =
      new PbKeyData()
          .setTypeUrl(KEY_TYPE)
          .setValue(key.serializeBinary())
          .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);

  return keyData;
}

async function createKeyData(
    opt_curveType?: PbEllipticCurveType, opt_hashType?: PbHashType,
    opt_encoding?: PbEcdsaSignatureEncoding): Promise<PbKeyData> {
  const key = await createKey(opt_curveType, opt_hashType, opt_encoding);
  return createKeyDataFromKey(key);
}

// Create set of keys with all possible predefined/supported parameters.
async function createTestSetOfKeys(): Promise<PbEcdsaPublicKey[]> {
  const keys: PbEcdsaPublicKey[] = [];
  keys.push(await createKey(
      PbEllipticCurveType.NIST_P256, PbHashType.SHA256,
      PbEcdsaSignatureEncoding.DER));
  keys.push(await createKey(
      PbEllipticCurveType.NIST_P256, PbHashType.SHA256,
      PbEcdsaSignatureEncoding.IEEE_P1363));
  keys.push(await createKey(
      PbEllipticCurveType.NIST_P384, PbHashType.SHA512,
      PbEcdsaSignatureEncoding.DER));
  keys.push(await createKey(
      PbEllipticCurveType.NIST_P384, PbHashType.SHA512,
      PbEcdsaSignatureEncoding.IEEE_P1363));
  keys.push(await createKey(
      PbEllipticCurveType.NIST_P521, PbHashType.SHA512,
      PbEcdsaSignatureEncoding.DER));
  keys.push(await createKey(
      PbEllipticCurveType.NIST_P521, PbHashType.SHA512,
      PbEcdsaSignatureEncoding.IEEE_P1363));
  return keys;
}

// Create set of keyData protos with keys of all possible predefined/supported
// parameters.
async function createTestSetOfKeyDatas(): Promise<PbKeyData[]> {
  const keys = await createTestSetOfKeys();
  const keyDatas: PbKeyData[] = [];
  for (const key of keys) {
    const keyData = await createKeyDataFromKey(key);
    keyDatas.push(keyData);
  }

  return keyDatas;
}
