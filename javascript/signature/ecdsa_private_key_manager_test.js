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
const PbEcdsaKeyFormat = goog.require('proto.google.crypto.tink.EcdsaKeyFormat');
const PbEcdsaParams = goog.require('proto.google.crypto.tink.EcdsaParams');
const PbEcdsaPrivateKey = goog.require('proto.google.crypto.tink.EcdsaPrivateKey');
const PbEcdsaPublicKey = goog.require('proto.google.crypto.tink.EcdsaPublicKey');
const PbEcdsaSignatureEncoding = goog.require('proto.google.crypto.tink.EcdsaSignatureEncoding');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PublicKeySign = goog.require('tink.PublicKeySign');
const PublicKeyVerify = goog.require('tink.PublicKeyVerify');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const TestCase = goog.require('goog.testing.TestCase');
const asserts = goog.require('goog.asserts');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');

const PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey';
const PRIVATE_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE;
const VERSION = 0;
const PRIVATE_KEY_MANAGER_PRIMITIVE = PublicKeySign;

const PUBLIC_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.EcdsaPublicKey';
const PUBLIC_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC;
const PUBLIC_KEY_MANAGER_PRIMITIVE = PublicKeyVerify;

testSuite({
  shouldRunTests() {
    return !userAgent.EDGE;  // b/120286783
  },

  setUp() {
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    Registry.reset();
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  async testNewKey_invalidSerializedKeyFormat() {
    const invalidSerializedKeyFormat = new Uint8Array(0);
    const manager = new EcdsaPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidSerializedKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.invalidSerializedKeyFormat(), e.toString());
    }
  },

  async testNewKey_unsupportedKeyFormatProto() {
    const unsupportedKeyFormatProto = new PbEcdsaParams();
    const manager = new EcdsaPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(unsupportedKeyFormatProto);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyFormat(), e.toString());
    }
  },

  async testNewKey_invalidFormat_missingParams() {
    const invalidFormat = new PbEcdsaKeyFormat();
    const manager = new EcdsaPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.invalidKeyFormatMissingParams(), e.toString());
    }
  },

  async testNewKey_invalidFormat_invalidParams() {
    const manager = new EcdsaPrivateKeyManager();

    // Unknown encoding.
    const invalidFormat = createKeyFormat();
    invalidFormat.getParams().setEncoding(
        PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownEncoding(), e.toString());
    }
    invalidFormat.getParams().setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    invalidFormat.getParams().setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownHash(), e.toString());
    }
    invalidFormat.getParams().setHashType(PbHashType.SHA256);

    // Unknown curve.
    invalidFormat.getParams().setCurve(PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownCurve(), e.toString());
    }

    // Bad hash + curve combinations.
    invalidFormat.getParams().setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256',
          e.toString());
    }

    invalidFormat.getParams().setCurve(PbEllipticCurveType.NIST_P521);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-512 (because curve is P-521) but got SHA-256',
          e.toString());
    }
  },

  async testNewKey_viaKeyFormat() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EcdsaPrivateKeyManager();

    for (let keyFormat of keyFormats) {
      const key = /** @type{!PbEcdsaPrivateKey} */ (
          await manager.getKeyFactory().newKey(keyFormat));

      assertObjectEquals(keyFormat.getParams(), key.getPublicKey().getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  },

  async testNewKeyData_invalidSerializedKeyFormat() {
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
        assertEquals(ExceptionText.invalidSerializedKeyFormat(), e.toString());
        continue;
      }
    }
  },

  async testNewKeyData_fromValidKeyFormat() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EcdsaPrivateKeyManager();

    for (let keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = /** @type{!PbKeyData} */ (
          await manager.getKeyFactory().newKeyData(serializedKeyFormat));

      assertEquals(PRIVATE_KEY_TYPE, keyData.getTypeUrl());
      assertEquals(PRIVATE_KEY_MATERIAL_TYPE, keyData.getKeyMaterialType());

      const key = PbEcdsaPrivateKey.deserializeBinary(keyData.getValue());
      assertObjectEquals(keyFormat.getParams(), key.getPublicKey().getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  },

  testGetPublicKeyData_invalidPrivateKeySerialization() {
    const manager = new EcdsaPrivateKeyManager();

    const privateKey = new Uint8Array([0, 1]);  // not a serialized private key
    try {
      const factory = /** @type {!KeyManager.PrivateKeyFactory} */ (
          manager.getKeyFactory());
      factory.getPublicKeyData(privateKey);
    } catch (e) {
      assertEquals(ExceptionText.invalidSerializedKey(), e.toString());
    }
  },

  async testGetPublicKeyData_shouldWork() {
    const keyFormat = createKeyFormat();
    const manager = new EcdsaPrivateKeyManager();

    const privateKey = /** @type{!PbEcdsaPrivateKey} */ (
        await manager.getKeyFactory().newKey(keyFormat));
    const factory =
        /** @type {!KeyManager.PrivateKeyFactory} */ (manager.getKeyFactory());
    const publicKeyData =
        factory.getPublicKeyData(privateKey.serializeBinary());

    assertEquals(PUBLIC_KEY_TYPE, publicKeyData.getTypeUrl());
    assertEquals(PUBLIC_KEY_MATERIAL_TYPE, publicKeyData.getKeyMaterialType());
    const publicKey =
        PbEcdsaPublicKey.deserializeBinary(publicKeyData.getValue());
    assertObjectEquals(
        privateKey.getPublicKey().getVersion(), publicKey.getVersion());
    assertObjectEquals(
        privateKey.getPublicKey().getParams(), publicKey.getParams());
    assertObjectEquals(privateKey.getPublicKey().getX(), publicKey.getX());
    assertObjectEquals(privateKey.getPublicKey().getY(), publicKey.getY());
  },

  async testGetPrimitive_unsupportedPrimitiveType() {
    const manager = new EcdsaPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const key = await manager.getKeyFactory().newKey(keyFormat);

    try {
      await manager.getPrimitive(PublicKeyVerify, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedPrimitive(), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeyDataType() {
    const manager = new EcdsaPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const keyData =
        (await manager.getKeyFactory().newKeyData(keyFormat.serializeBinary()))
            .setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.unsupportedKeyType(keyData.getTypeUrl()), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeyType() {
    const manager = new EcdsaPrivateKeyManager();
    let key = new PbEcdsaPublicKey();

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyType(), e.toString());
    }
  },

  async testGetPrimitive_highVersion() {
    const manager = new EcdsaPrivateKeyManager();
    const version = manager.getVersion() + 1;
    const keyFormat = createKeyFormat();
    const key = asserts
                    .assertInstanceof(
                        await manager.getKeyFactory().newKey(keyFormat),
                        PbEcdsaPrivateKey)
                    .setVersion(version);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.versionOutOfBounds(), e.toString());
    }
  },

  async testGetPrimitive_invalidParams() {
    const manager = new EcdsaPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const key = asserts.assertInstanceof(
        await manager.getKeyFactory().newKey(keyFormat), PbEcdsaPrivateKey);

    // Unknown encoding.
    key.getPublicKey().getParams().setEncoding(
        PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownEncoding(), e.toString());
    }
    key.getPublicKey().getParams().setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    key.getPublicKey().getParams().setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownHash(), e.toString());
    }
    key.getPublicKey().getParams().setHashType(PbHashType.SHA256);

    // Unknown curve.
    key.getPublicKey().getParams().setCurve(PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownCurve(), e.toString());
    }

    // Bad hash + curve combinations.
    key.getPublicKey().getParams().setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256',
          e.toString());
    }

    key.getPublicKey().getParams().setCurve(PbEllipticCurveType.NIST_P521);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-512 (because curve is P-521) but got SHA-256',
          e.toString());
    }
  },

  async testGetPrimitive_invalidSerializedKey() {
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
        assertEquals(ExceptionText.invalidSerializedKey(), e.toString());
      }
    }
  },

  async testGetPrimitive_fromKey() {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new EcdsaPrivateKeyManager();
    const publicKeyManager = new EcdsaPublicKeyManager();

    for (let keyFormat of keyFormats) {
      const key = asserts.assertInstanceof(
          await privateKeyManager.getKeyFactory().newKey(keyFormat),
          PbEcdsaPrivateKey);

      const /** !PublicKeyVerify */ publicKeyVerify =
          asserts.assert(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE,
              asserts.assert(key.getPublicKey())));
      const /** !PublicKeySign */ publicKeySign =
          asserts.assert(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, key));

      const data = Random.randBytes(10);
      const signature = await publicKeySign.sign(data);
      const isValid = await publicKeyVerify.verify(signature, data);

      assertTrue(isValid);
    }
  },

  async testGetPrimitive_fromKeyData() {
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
          asserts.assert(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, publicKeyData));
      const /** !PublicKeySign */ publicKeySign =
          asserts.assert(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, keyData));

      const data = Random.randBytes(10);
      const signature = await publicKeySign.sign(data);
      const isValid = await publicKeyVerify.verify(signature, data);

      assertTrue(isValid);
    }
  },

  testDoesSupport() {
    const manager = new EcdsaPrivateKeyManager();
    assertTrue(manager.doesSupport(PRIVATE_KEY_TYPE));
  },

  testGetKeyType() {
    const manager = new EcdsaPrivateKeyManager();
    assertEquals(PRIVATE_KEY_TYPE, manager.getKeyType());
  },

  testGetPrimitiveType() {
    const manager = new EcdsaPrivateKeyManager();
    assertEquals(PRIVATE_KEY_MANAGER_PRIMITIVE, manager.getPrimitiveType());
  },

  testGetVersion() {
    const manager = new EcdsaPrivateKeyManager();
    assertEquals(VERSION, manager.getVersion());
  },
});

// Helper classes and functions
class ExceptionText {
  /** @return {string} */
  static nullKeyFormat() {
    return 'CustomError: Key format has to be non-null.';
  }

  /** @return {string} */
  static invalidSerializedKeyFormat() {
    return 'CustomError: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
        ' key format proto.';
  }

  /** @return {string} */
  static unsupportedPrimitive() {
    return 'CustomError: Requested primitive type which is not supported by ' +
        'this key manager.';
  }

  /** @return {string} */
  static unsupportedKeyFormat() {
    return 'CustomError: Expected ' + PRIVATE_KEY_TYPE + ' key format proto.';
  }

  /**
   * @param {string=} opt_requestedKeyType
   * @return {string}
   */
  static unsupportedKeyType(opt_requestedKeyType) {
    const prefix = 'CustomError: Key type';
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
    return 'CustomError: Invalid public key - missing signature encoding.';
  }

  /** @return {string} */
  static unknownHash() {
    return 'CustomError: Unknown hash type.';
  }

  /** @return {string} */
  static unknownCurve() {
    return 'CustomError: Unknown curve type.';
  }

  /** @return {string} */
  static versionOutOfBounds() {
    return 'CustomError: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  /** @return {string} */
  static invalidKeyFormatMissingParams() {
    return 'CustomError: Invalid key format - missing params.';
  }

  /** @return {string} */
  static invalidSerializedKey() {
    return 'CustomError: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
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
