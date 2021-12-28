/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbEcdsaKeyFormat, PbEcdsaParams, PbEcdsaPrivateKey, PbEcdsaPublicKey, PbEcdsaSignatureEncoding, PbEllipticCurveType, PbHashType, PbKeyData} from '../internal/proto';
import * as Registry from '../internal/registry';
import * as Random from '../subtle/random';
import {assertExists, assertInstanceof} from '../testing/internal/test_utils';

import {EcdsaPrivateKeyManager} from './ecdsa_private_key_manager';
import {EcdsaPublicKeyManager} from './ecdsa_public_key_manager';
import {PublicKeySign} from './internal/public_key_sign';
import {PublicKeyVerify} from './internal/public_key_verify';

const PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey';
const PRIVATE_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE;
const VERSION = 0;
const PRIVATE_KEY_MANAGER_PRIMITIVE = PublicKeySign;

const PUBLIC_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.EcdsaPublicKey';
const PUBLIC_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC;
const PUBLIC_KEY_MANAGER_PRIMITIVE = PublicKeyVerify;

describe('ecdsa private key manager test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    Registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('new key, invalid serialized key format', async function() {
    const invalidSerializedKeyFormat = new Uint8Array(0);
    const manager = new EcdsaPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidSerializedKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
    }
  });

  it('new key, unsupported key format proto', async function() {
    const unsupportedKeyFormatProto = new PbEcdsaParams();
    const manager = new EcdsaPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(unsupportedKeyFormatProto);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyFormat());
    }
  });

  it('new key, invalid format, missing params', async function() {
    const invalidFormat = new PbEcdsaKeyFormat();
    const manager = new EcdsaPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidKeyFormatMissingParams());
    }
  });

  it('new key, invalid format, invalid params', async function() {
    const manager = new EcdsaPrivateKeyManager();

    // Unknown encoding.
    const invalidFormat = createKeyFormat();
    invalidFormat.getParams()?.setEncoding(
        PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownEncoding());
    }
    invalidFormat.getParams()?.setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    invalidFormat.getParams()?.setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownHash());
    }
    invalidFormat.getParams()?.setHashType(PbHashType.SHA256);

    // Unknown curve.
    invalidFormat.getParams()?.setCurve(PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownCurve());
    }

    // Bad hash + curve combinations.
    invalidFormat.getParams()?.setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256');
    }
    invalidFormat.getParams()?.setCurve(PbEllipticCurveType.NIST_P521);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-512 (because curve is P-521) but got SHA-256');
    }
  });

  it('new key, via key format', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EcdsaPrivateKeyManager();
    for (const keyFormat of keyFormats) {
      const key = await manager.getKeyFactory().newKey(keyFormat);

      expect(key.getPublicKey()?.getParams()).toEqual(keyFormat.getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  });

  it('new key data, invalid serialized key format', async function() {
    const serializedKeyFormats = [new Uint8Array(1), new Uint8Array(0)];
    const manager = new EcdsaPrivateKeyManager();

    const serializedKeyFormatsLength = serializedKeyFormats.length;
    for (let i = 0; i < serializedKeyFormatsLength; i++) {
      try {
        await manager.getKeyFactory().newKeyData(serializedKeyFormats[i]);
        fail(
            'An exception should be thrown for the string: ' +
            serializedKeyFormats[i]);
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
        continue;
      }
    }
  });

  it('new key data, from valid key format', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EcdsaPrivateKeyManager();
    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData =
          await manager.getKeyFactory().newKeyData(serializedKeyFormat);
      expect(keyData.getTypeUrl()).toBe(PRIVATE_KEY_TYPE);
      expect(keyData.getKeyMaterialType()).toBe(PRIVATE_KEY_MATERIAL_TYPE);

      const key = PbEcdsaPrivateKey.deserializeBinary(keyData.getValue_asU8());
      expect(key.getPublicKey()?.getParams()).toEqual(keyFormat.getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  });

  it('get public key data, invalid private key serialization', function() {
    const manager = new EcdsaPrivateKeyManager();

    const privateKey = new Uint8Array([0, 1]);  // not a serialized private key
    try {
      const factory = manager.getKeyFactory();
      factory.getPublicKeyData(privateKey);
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
    }
  });

  it('get public key data, should work', async function() {
    const keyFormat = createKeyFormat();
    const manager = new EcdsaPrivateKeyManager();
    const privateKey = await manager.getKeyFactory().newKey(keyFormat);
    const factory = (manager.getKeyFactory());
    const publicKeyData =
        factory.getPublicKeyData(privateKey.serializeBinary());

    expect(publicKeyData.getTypeUrl()).toBe(PUBLIC_KEY_TYPE);
    expect(publicKeyData.getKeyMaterialType()).toBe(PUBLIC_KEY_MATERIAL_TYPE);
    const publicKey =
        PbEcdsaPublicKey.deserializeBinary(publicKeyData.getValue_asU8());
    expect(publicKey.getVersion())
        .toEqual(privateKey.getPublicKey()!.getVersion());
    expect(publicKey.getParams())
        .toEqual(privateKey.getPublicKey()!.getParams());
    expect(publicKey.getX_asU8())
        .toEqual(privateKey.getPublicKey()!.getX_asU8());
    expect(publicKey.getY_asU8())
        .toEqual(privateKey.getPublicKey()!.getY_asU8());
  });

  it('get primitive, unsupported key data type', async function() {
    const manager = new EcdsaPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const keyData =
        (await manager.getKeyFactory().newKeyData(keyFormat.serializeBinary()))
            .setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyType(keyData.getTypeUrl()));
    }
  });

  it('get primitive, unsupported key type', async function() {
    const manager = new EcdsaPrivateKeyManager();
    const key = new PbEcdsaPublicKey();

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyType());
    }
  });

  it('get primitive, high version', async function() {
    const manager = new EcdsaPrivateKeyManager();
    const version = manager.getVersion() + 1;
    const keyFormat = createKeyFormat();
    const key =
        assertInstanceof(
            await manager.getKeyFactory().newKey(keyFormat), PbEcdsaPrivateKey)
            .setVersion(version);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.versionOutOfBounds());
    }
  });

  it('get primitive, invalid params', async function() {
    const manager = new EcdsaPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const key = assertInstanceof(
        await manager.getKeyFactory().newKey(keyFormat), PbEcdsaPrivateKey);

    // Unknown encoding.
    key.getPublicKey()?.getParams()?.setEncoding(
        PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownEncoding());
    }
    key.getPublicKey()?.getParams()?.setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    key.getPublicKey()?.getParams()?.setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownHash());
    }
    key.getPublicKey()?.getParams()?.setHashType(PbHashType.SHA256);

    // Unknown curve.
    key.getPublicKey()?.getParams()?.setCurve(
        PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownCurve());
    }

    // Bad hash + curve combinations.
    key.getPublicKey()?.getParams()?.setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256');
    }
    key.getPublicKey()?.getParams()?.setCurve(PbEllipticCurveType.NIST_P521);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-512 (because curve is P-521) but got SHA-256');
    }
  });

  it('get primitive, invalid serialized key', async function() {
    const manager = new EcdsaPrivateKeyManager();
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
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
      }
    }
  });

  it('get primitive, from key', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new EcdsaPrivateKeyManager();
    const publicKeyManager = new EcdsaPublicKeyManager();
    for (const keyFormat of keyFormats) {
      const key = assertInstanceof(
          await privateKeyManager.getKeyFactory().newKey(keyFormat),
          PbEcdsaPrivateKey);
      const publicKeyVerify: PublicKeyVerify =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, assertExists(key.getPublicKey())));
      const publicKeySign: PublicKeySign =
          assertExists(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, key));

      const data = Random.randBytes(10);
      const signature = await publicKeySign.sign(data);
      const isValid = await publicKeyVerify.verify(signature, data);

      expect(isValid).toBe(true);
    }
  });

  it('get primitive, from key data', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new EcdsaPrivateKeyManager();
    const publicKeyManager = new EcdsaPublicKeyManager();

    for (const keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = await privateKeyManager.getKeyFactory().newKeyData(
          serializedKeyFormat);
      const factory = privateKeyManager.getKeyFactory();
      const publicKeyData = factory.getPublicKeyData(keyData.getValue_asU8());

      const publicKeyVerify: PublicKeyVerify =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, publicKeyData));
      const publicKeySign: PublicKeySign =
          assertExists(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, keyData));

      const data = Random.randBytes(10);
      const signature = await publicKeySign.sign(data);
      const isValid = await publicKeyVerify.verify(signature, data);

      expect(isValid).toBe(true);
    }
  });

  it('does support', function() {
    const manager = new EcdsaPrivateKeyManager();
    expect(manager.doesSupport(PRIVATE_KEY_TYPE)).toBe(true);
  });

  it('get key type', function() {
    const manager = new EcdsaPrivateKeyManager();
    expect(manager.getKeyType()).toBe(PRIVATE_KEY_TYPE);
  });

  it('get primitive type', function() {
    const manager = new EcdsaPrivateKeyManager();
    expect(manager.getPrimitiveType()).toBe(PRIVATE_KEY_MANAGER_PRIMITIVE);
  });

  it('get version', function() {
    const manager = new EcdsaPrivateKeyManager();
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

  static unknownEncoding(): string {
    return 'SecurityException: Invalid public key - missing signature encoding.';
  }

  static unknownHash(): string {
    return 'SecurityException: Unknown hash type.';
  }

  static unknownCurve(): string {
    return 'SecurityException: Unknown curve type.';
  }

  static versionOutOfBounds(): string {
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  static invalidKeyFormatMissingParams(): string {
    return 'SecurityException: Invalid key format - missing params.';
  }

  static invalidSerializedKey(): string {
    return 'SecurityException: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
        ' key-proto.';
  }
}

function createParams(
    curveType: PbEllipticCurveType, hashType: PbHashType,
    encoding: PbEcdsaSignatureEncoding): PbEcdsaParams {
  const params =
      new PbEcdsaParams().setCurve(curveType).setHashType(hashType).setEncoding(
          encoding);

  return params;
}

function createKeyFormat(
    opt_curveType: PbEllipticCurveType = PbEllipticCurveType.NIST_P256,
    opt_hashType: PbHashType = PbHashType.SHA256,
    opt_encodingType: PbEcdsaSignatureEncoding =
        PbEcdsaSignatureEncoding.DER): PbEcdsaKeyFormat {
  const keyFormat = new PbEcdsaKeyFormat().setParams(
      createParams(opt_curveType, opt_hashType, opt_encodingType));
  return keyFormat;
}

/**
 * Create set of key formats with all possible predefined/supported parameters.
 */
function createTestSetOfKeyFormats(): PbEcdsaKeyFormat[] {
  const keyFormats: PbEcdsaKeyFormat[] = [];
  keyFormats.push(createKeyFormat(
      PbEllipticCurveType.NIST_P256, PbHashType.SHA256,
      PbEcdsaSignatureEncoding.DER));
  keyFormats.push(createKeyFormat(
      PbEllipticCurveType.NIST_P256, PbHashType.SHA256,
      PbEcdsaSignatureEncoding.IEEE_P1363));
  keyFormats.push(createKeyFormat(
      PbEllipticCurveType.NIST_P384, PbHashType.SHA512,
      PbEcdsaSignatureEncoding.DER));
  keyFormats.push(createKeyFormat(
      PbEllipticCurveType.NIST_P384, PbHashType.SHA512,
      PbEcdsaSignatureEncoding.IEEE_P1363));
  keyFormats.push(createKeyFormat(
      PbEllipticCurveType.NIST_P521, PbHashType.SHA512,
      PbEcdsaSignatureEncoding.DER));
  keyFormats.push(createKeyFormat(
      PbEllipticCurveType.NIST_P521, PbHashType.SHA512,
      PbEcdsaSignatureEncoding.IEEE_P1363));
  return keyFormats;
}
