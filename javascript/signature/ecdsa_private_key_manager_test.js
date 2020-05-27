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

goog.module('tink.signature.EcdsaPrivateKeyManagerTest');
goog.setTestOnly('tink.signature.EcdsaPrivateKeyManagerTest');

const EcdsaPrivateKeyManager = goog.require('tink.signature.EcdsaPrivateKeyManager');
const EcdsaPublicKeyManager = goog.require('tink.signature.EcdsaPublicKeyManager');
const KeyManager = goog.require('tink.KeyManager');
const {PublicKeySign} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_sign');
const {PublicKeyVerify} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_verify');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const {PbEcdsaKeyFormat, PbEcdsaParams, PbEcdsaPrivateKey, PbEcdsaPublicKey, PbEcdsaSignatureEncoding, PbEllipticCurveType, PbHashType, PbKeyData} = goog.require('google3.third_party.tink.javascript.internal.proto');
const {assertExists, assertInstanceof} = goog.require('google3.third_party.tink.javascript.testing.internal.test_utils');

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
    invalidFormat.getParams().setEncoding(
        PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownEncoding());
    }
    invalidFormat.getParams().setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    invalidFormat.getParams().setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownHash());
    }
    invalidFormat.getParams().setHashType(PbHashType.SHA256);

    // Unknown curve.
    invalidFormat.getParams().setCurve(PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownCurve());
    }

    // Bad hash + curve combinations.
    invalidFormat.getParams().setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256');
    }

    invalidFormat.getParams().setCurve(PbEllipticCurveType.NIST_P521);
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

    for (let keyFormat of keyFormats) {
      const key = /** @type{!PbEcdsaPrivateKey} */ (
          await manager.getKeyFactory().newKey(keyFormat));

      expect(key.getPublicKey().getParams()).toEqual(keyFormat.getParams());
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

    for (let keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = /** @type{!PbKeyData} */ (
          await manager.getKeyFactory().newKeyData(serializedKeyFormat));

      expect(keyData.getTypeUrl()).toBe(PRIVATE_KEY_TYPE);
      expect(keyData.getKeyMaterialType()).toBe(PRIVATE_KEY_MATERIAL_TYPE);

      const key = PbEcdsaPrivateKey.deserializeBinary(keyData.getValue());
      expect(key.getPublicKey().getParams()).toEqual(keyFormat.getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  });

  it('get public key data, invalid private key serialization', function() {
    const manager = new EcdsaPrivateKeyManager();

    const privateKey = new Uint8Array([0, 1]);  // not a serialized private key
    try {
      const factory = /** @type {!KeyManager.PrivateKeyFactory} */ (
          manager.getKeyFactory());
      factory.getPublicKeyData(privateKey);
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
    }
  });

  it('get public key data, should work', async function() {
    const keyFormat = createKeyFormat();
    const manager = new EcdsaPrivateKeyManager();

    const privateKey = /** @type{!PbEcdsaPrivateKey} */ (
        await manager.getKeyFactory().newKey(keyFormat));
    const factory =
        /** @type {!KeyManager.PrivateKeyFactory} */ (manager.getKeyFactory());
    const publicKeyData =
        factory.getPublicKeyData(privateKey.serializeBinary());

    expect(publicKeyData.getTypeUrl()).toBe(PUBLIC_KEY_TYPE);
    expect(publicKeyData.getKeyMaterialType()).toBe(PUBLIC_KEY_MATERIAL_TYPE);
    const publicKey =
        PbEcdsaPublicKey.deserializeBinary(publicKeyData.getValue());
    expect(publicKey.getVersion())
        .toEqual(privateKey.getPublicKey().getVersion());
    expect(publicKey.getParams())
        .toEqual(privateKey.getPublicKey().getParams());
    expect(publicKey.getX()).toEqual(privateKey.getPublicKey().getX());
    expect(publicKey.getY()).toEqual(privateKey.getPublicKey().getY());
  });

  it('get primitive, unsupported primitive type', async function() {
    const manager = new EcdsaPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const key = await manager.getKeyFactory().newKey(keyFormat);

    try {
      await manager.getPrimitive(PublicKeyVerify, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedPrimitive());
    }
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
    let key = new PbEcdsaPublicKey();

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
    key.getPublicKey().getParams().setEncoding(
        PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownEncoding());
    }
    key.getPublicKey().getParams().setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    key.getPublicKey().getParams().setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownHash());
    }
    key.getPublicKey().getParams().setHashType(PbHashType.SHA256);

    // Unknown curve.
    key.getPublicKey().getParams().setCurve(PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownCurve());
    }

    // Bad hash + curve combinations.
    key.getPublicKey().getParams().setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256');
    }

    key.getPublicKey().getParams().setCurve(PbEllipticCurveType.NIST_P521);
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

    for (let keyFormat of keyFormats) {
      const key = assertInstanceof(
          await privateKeyManager.getKeyFactory().newKey(keyFormat),
          PbEcdsaPrivateKey);

      const /** !PublicKeyVerify */ publicKeyVerify =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, assertExists(key.getPublicKey())));
      const /** !PublicKeySign */ publicKeySign =
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

    for (let keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = await privateKeyManager.getKeyFactory().newKeyData(
          serializedKeyFormat);
      const factory = /** @type {!KeyManager.PrivateKeyFactory} */ (
          privateKeyManager.getKeyFactory());
      const publicKeyData = factory.getPublicKeyData(keyData.getValue_asU8());

      const /** !PublicKeyVerify */ publicKeyVerify =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, publicKeyData));
      const /** !PublicKeySign */ publicKeySign =
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
  /** @return {string} */
  static nullKeyFormat() {
    return 'SecurityException: Key format has to be non-null.';
  }

  /** @return {string} */
  static invalidSerializedKeyFormat() {
    return 'SecurityException: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
        ' key format proto.';
  }

  /** @return {string} */
  static unsupportedPrimitive() {
    return 'SecurityException: Requested primitive type which is not supported by ' +
        'this key manager.';
  }

  /** @return {string} */
  static unsupportedKeyFormat() {
    return 'SecurityException: Expected ' + PRIVATE_KEY_TYPE +
        ' key format proto.';
  }

  /**
   * @param {string=} opt_requestedKeyType
   * @return {string}
   */
  static unsupportedKeyType(opt_requestedKeyType) {
    const prefix = 'SecurityException: Key type';
    const suffix =
        'is not supported. This key manager supports ' + PRIVATE_KEY_TYPE + '.';
    if (opt_requestedKeyType) {
      return prefix + ' ' + opt_requestedKeyType + ' ' + suffix;
    } else {
      return prefix + ' ' + suffix;
    }
  }

  /** @return {string} */
  static unknownEncoding() {
    return 'SecurityException: Invalid public key - missing signature encoding.';
  }

  /** @return {string} */
  static unknownHash() {
    return 'SecurityException: Unknown hash type.';
  }

  /** @return {string} */
  static unknownCurve() {
    return 'SecurityException: Unknown curve type.';
  }

  /** @return {string} */
  static versionOutOfBounds() {
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  /** @return {string} */
  static invalidKeyFormatMissingParams() {
    return 'SecurityException: Invalid key format - missing params.';
  }

  /** @return {string} */
  static invalidSerializedKey() {
    return 'SecurityException: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
        ' key-proto.';
  }
}

/**
 * @param {!PbEllipticCurveType} curveType
 * @param {!PbHashType} hashType
 * @param {!PbEcdsaSignatureEncoding} encoding
 *
 * @return {!PbEcdsaParams}
 */
const createParams = function(curveType, hashType, encoding) {
  const params =
      new PbEcdsaParams().setCurve(curveType).setHashType(hashType).setEncoding(
          encoding);

  return params;
};

/**
 * @param {!PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {!PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbEcdsaSignatureEncoding=} opt_encodingType (default: DER)
 *
 * @return {!PbEcdsaKeyFormat}
 */
const createKeyFormat = function(
    opt_curveType = PbEllipticCurveType.NIST_P256,
    opt_hashType = PbHashType.SHA256,
    opt_encodingType = PbEcdsaSignatureEncoding.DER) {
  const keyFormat = new PbEcdsaKeyFormat().setParams(
      createParams(opt_curveType, opt_hashType, opt_encodingType));
  return keyFormat;
};

// Create set of key formats with all possible predefined/supported parameters.
/** @return {!Array<!PbEcdsaKeyFormat>} */
const createTestSetOfKeyFormats = function() {
  const /** !Array<!PbEcdsaKeyFormat> */ keyFormats = [];
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
};
