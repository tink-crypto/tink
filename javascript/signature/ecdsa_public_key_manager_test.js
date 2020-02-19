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

goog.module('tink.signature.EcdsaPublicKeyManagerTest');
goog.setTestOnly('tink.signature.EcdsaPublicKeyManagerTest');

const Bytes = goog.require('tink.subtle.Bytes');
const EcdsaPublicKeyManager = goog.require('tink.signature.EcdsaPublicKeyManager');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Mac = goog.require('tink.Mac');
const PbEcdsaParams = goog.require('proto.google.crypto.tink.EcdsaParams');
const PbEcdsaPublicKey = goog.require('proto.google.crypto.tink.EcdsaPublicKey');
const PbEcdsaSignatureEncoding = goog.require('proto.google.crypto.tink.EcdsaSignatureEncoding');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PublicKeyVerify = goog.require('tink.PublicKeyVerify');
const Registry = goog.require('tink.Registry');
const TestCase = goog.require('goog.testing.TestCase');
const Util = goog.require('tink.Util');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');

const KEY_TYPE = 'type.googleapis.com/google.crypto.tink.EcdsaPublicKey';
const VERSION = 0;
const PRIMITIVE = PublicKeyVerify;

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

  testNewKey() {
    const manager = new EcdsaPublicKeyManager();

    try {
      manager.getKeyFactory().newKey(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.notSupported(), e.toString());
    }
  },

  testNewKeyData() {
    const manager = new EcdsaPublicKeyManager();

    try {
      manager.getKeyFactory().newKeyData(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.notSupported(), e.toString());
    }
  },

  async testGetPrimitive_unsupportedPrimitiveType() {
    const manager = new EcdsaPublicKeyManager();
    const key = await createKey();

    try {
      await manager.getPrimitive(Mac, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedPrimitive(), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeyDataType() {
    const manager = new EcdsaPublicKeyManager();
    const keyData =
        (await createKeyData()).setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.unsupportedKeyType(keyData.getTypeUrl()), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeyType() {
    const manager = new EcdsaPublicKeyManager();
    let key = new PbEcdsaParams();

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyType(), e.toString());
    }
  },

  async testGetPrimitive_highVersion() {
    const version = 1;
    const manager = new EcdsaPublicKeyManager();
    const key = (await createKey()).setVersion(version);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.versionOutOfBounds(), e.toString());
    }
  },

  async testGetPrimitive_missingParams() {
    const manager = new EcdsaPublicKeyManager();
    const key = (await createKey()).setParams(null);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingParams(), e.toString());
    }
  },

  async testGetPrimitive_invalidParams() {
    const manager = new EcdsaPublicKeyManager();
    const key = await createKey();

    // Unknown encoding.
    key.getParams().setEncoding(PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownEncoding(), e.toString());
    }
    key.getParams().setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    key.getParams().setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownHash(), e.toString());
    }
    key.getParams().setHashType(PbHashType.SHA256);

    // Unknown curve.
    key.getParams().setCurve(PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownCurve(), e.toString());
    }

    // Bad hash + curve combinations.
    key.getParams().setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256',
          e.toString());
    }

    key.getParams().setCurve(PbEllipticCurveType.NIST_P521);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-512 (because curve is P-521) but got SHA-256',
          e.toString());
    }
  },

  async testGetPrimitive_invalidKey() {
    const manager = new EcdsaPublicKeyManager();
    const key = await createKey();
    const x = key.getX();
    key.setX(new Uint8Array(0));

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.webCryptoError(), e.toString());
    }

    key.setX(x);
    key.setY(new Uint8Array(0));
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.webCryptoError(), e.toString());
    }
  },

  async testGetPrimitive_invalidSerializedKey() {
    const manager = new EcdsaPublicKeyManager();
    const keyData = await createKeyData();

    for (let i = 0; i < 2; ++i) {
      // Set the value of keyData to something which is not a serialization of a
      // proper key.
      keyData.setValue(new Uint8Array(i));
      try {
        await manager.getPrimitive(PRIMITIVE, keyData);
        fail('An exception should be thrown ' + i.toString());
      } catch (e) {
        assertEquals(ExceptionText.invalidSerializedKey(), e.toString());
      }
    }
  },

  // tests for getting primitive from valid key/keyData
  async testGetPrimitive_fromKey() {
    const manager = new EcdsaPublicKeyManager();
    const keys = await createTestSetOfKeys();

    for (let key of keys) {
      await manager.getPrimitive(PRIMITIVE, key);
    }
  },

  async testGetPrimitive_fromKeyData() {
    const manager = new EcdsaPublicKeyManager();
    const keyDatas = await createTestSetOfKeyDatas();

    for (let key of keyDatas) {
      await manager.getPrimitive(PRIMITIVE, key);
    }
  },

  testDoesSupport() {
    const manager = new EcdsaPublicKeyManager();

    assertTrue(manager.doesSupport(KEY_TYPE));
  },

  testGetKeyType() {
    const manager = new EcdsaPublicKeyManager();

    assertEquals(KEY_TYPE, manager.getKeyType());
  },

  testGetPrimitiveType() {
    const manager = new EcdsaPublicKeyManager();

    assertEquals(PRIMITIVE, manager.getPrimitiveType());
  },

  testGetVersion() {
    const manager = new EcdsaPublicKeyManager();

    assertEquals(VERSION, manager.getVersion());
  },
});

// Helper classes and functions
class ExceptionText {
  /** @return {string} */
  static notSupported() {
    return 'CustomError: This operation is not supported for public keys. ' +
        'Use EcdsaPrivateKeyManager to generate new keys.';
  }

  /** @return {string} */
  static unsupportedPrimitive() {
    return 'CustomError: Requested primitive type which is not supported by ' +
        'this key manager.';
  }

  /**
   * @param {string=} opt_requestedKeyType
   * @return {string}
   */
  static unsupportedKeyType(opt_requestedKeyType) {
    const prefix = 'CustomError: Key type';
    const suffix =
        'is not supported. This key manager supports ' + KEY_TYPE + '.';
    if (opt_requestedKeyType) {
      return prefix + ' ' + opt_requestedKeyType + ' ' + suffix;
    } else {
      return prefix + ' ' + suffix;
    }
  }

  /** @return {string} */
  static versionOutOfBounds() {
    return 'CustomError: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
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
  static missingParams() {
    return 'CustomError: Invalid public key - missing params.';
  }

  /** @return {string} */
  static missingXY() {
    return 'CustomError: Invalid public key - missing value of X or Y.';
  }

  /** @return {string} */
  static invalidSerializedKey() {
    return 'CustomError: Input cannot be parsed as ' + KEY_TYPE + ' key-proto.';
  }

  /** @return {string} */
  static webCryptoError() {
    return userAgent.GECKO ?
        'DataError: Data provided to an operation does not meet requirements' :
        'DataError';
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
 * @param {!PbEcdsaSignatureEncoding=} opt_encoding (default: DER)
 *
 * @return {!Promise<!PbEcdsaPublicKey>}
 */
const createKey = async function(
    opt_curveType = PbEllipticCurveType.NIST_P256,
    opt_hashType = PbHashType.SHA256,
    opt_encoding = PbEcdsaSignatureEncoding.DER) {
  const curveSubtleType = Util.curveTypeProtoToSubtle(opt_curveType);
  const curveName = EllipticCurves.curveToString(curveSubtleType);

  const key = new PbEcdsaPublicKey().setVersion(0).setParams(
      createParams(opt_curveType, opt_hashType, opt_encoding));

  const keyPair = await EllipticCurves.generateKeyPair('ECDSA', curveName);
  const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey);
  key.setX(Bytes.fromBase64(publicKey['x'], /* opt_webSafe = */ true));
  key.setY(Bytes.fromBase64(publicKey['y'], /* opt_webSafe = */ true));

  return key;
};

/**
 * @param {!PbEcdsaPublicKey} key
 *
 * @return {!PbKeyData}
 */
const createKeyDataFromKey = function(key) {
  const keyData =
      new PbKeyData()
          .setTypeUrl(KEY_TYPE)
          .setValue(key.serializeBinary())
          .setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);

  return keyData;
};

/**
 * @param {!PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {!PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbEcdsaSignatureEncoding=} opt_encoding (default: DER)
 *
 * @return {!Promise<!PbKeyData>}
 */
const createKeyData =
    async function(opt_curveType, opt_hashType, opt_encoding) {
  const key = await createKey(opt_curveType, opt_hashType, opt_encoding);
  return createKeyDataFromKey(key);
};


// Create set of keys with all possible predefined/supported parameters.
/** @return {!Promise<!Array<!PbEcdsaPublicKey>>} */
const createTestSetOfKeys = async function() {
  const /** !Array<!PbEcdsaPublicKey> */ keys = [];
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
};

// Create set of keyData protos with keys of all possible predefined/supported
// parameters.
/** @return {!Promise<!Array<!PbKeyData>>} */
const createTestSetOfKeyDatas = async function() {
  const keys = await createTestSetOfKeys();

  const /** !Array<!PbKeyData> */ keyDatas = [];
  for (let key of keys) {
    const keyData = await createKeyDataFromKey(key);
    keyDatas.push(keyData);
  }

  return keyDatas;
};
