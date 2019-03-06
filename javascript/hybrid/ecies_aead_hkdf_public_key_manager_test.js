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

goog.module('tink.hybrid.EciesAeadHkdfPublicKeyManagerTest');
goog.setTestOnly('tink.hybrid.EciesAeadHkdfPublicKeyManagerTest');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const Bytes = goog.require('tink.subtle.Bytes');
const EciesAeadHkdfPublicKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPublicKeyManager');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const HybridEncrypt = goog.require('tink.HybridEncrypt');
const Mac = goog.require('tink.Mac');
const PbAesCtrKey = goog.require('proto.google.crypto.tink.AesCtrKey');
const PbEciesAeadDemParams = goog.require('proto.google.crypto.tink.EciesAeadDemParams');
const PbEciesAeadHkdfParams = goog.require('proto.google.crypto.tink.EciesAeadHkdfParams');
const PbEciesAeadHkdfPublicKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPublicKey');
const PbEciesHkdfKemParams = goog.require('proto.google.crypto.tink.EciesHkdfKemParams');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbKeyData = goog.require('proto.google.crypto.tink.KeyData');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbPointFormat = goog.require('proto.google.crypto.tink.EcPointFormat');
const Random = goog.require('tink.subtle.Random');
const Registry = goog.require('tink.Registry');
const TestCase = goog.require('goog.testing.TestCase');
const Util = goog.require('tink.Util');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');

const KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
const VERSION = 0;
const PRIMITIVE = HybridEncrypt;

testSuite({
  shouldRunTests() {
    return !userAgent.EDGE;  // b/120286783
  },

  setUp() {
    AeadConfig.register();
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    Registry.reset();
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  testNewKey() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    try {
      manager.getKeyFactory().newKey();
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.notSupported(), e.toString());
    }
  },

  testNewKeyData() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    try {
      manager.getKeyFactory().newKeyData();
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.notSupported(), e.toString());
    }
  },

  async testGetPrimitive_unsupportedPrimitiveType() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = await createKey();

    try {
      await manager.getPrimitive(Mac, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedPrimitive(), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeyDataType() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const /** PbKeyData */ keyData = await createKeyData();
    keyData.setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.unsupportedKeyType(keyData.getTypeUrl()), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeyType() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    let key = new PbAesCtrKey();

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyType(), e.toString());
    }
  },

  async testGetPrimitive_highVersion() {
    const version = 1;
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = await createKey();
    key.setVersion(version);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.versionOutOfBounds(), e.toString());
    }
  },

  async testGetPrimitive_missingParams() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = await createKey();
    key.setParams(null);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingParams(), e.toString());
    }
  },

  async testGetPrimitive_invalidParams() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = await createKey();

    // unknown point format
    key.getParams().setEcPointFormat(PbPointFormat.UNKNOWN_FORMAT);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownPointFormat(), e.toString());
    }
    key.getParams().setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    key.getParams().setKemParams(null);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingKemParams(), e.toString());
    }
    key.getParams().setKemParams(createKemParams());

    // unsupported AEAD key template
    const typeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    key.getParams().getDemParams().getAeadDem().setTypeUrl(typeUrl);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyTemplate(typeUrl), e.toString());
    }
  },

  async testGetPrimitive_invalidKey() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = await createKey();
    key.setX(null);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingXY(), e.toString());
    }
    key.getParams().setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    key.getParams().setKemParams(null);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingKemParams(), e.toString());
    }
    key.getParams().setKemParams(createKemParams());

    // unsupported AEAD key template
    const typeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    key.getParams().getDemParams().getAeadDem().setTypeUrl(typeUrl);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyTemplate(typeUrl), e.toString());
    }
  },

  async testGetPrimitive_invalidSerializedKey() {
    const manager = new EciesAeadHkdfPublicKeyManager();
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
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keys = await createTestSetOfKeys();

    for (let key of keys) {
      const /** HybridEncrypt */ primitive =
          await manager.getPrimitive(PRIMITIVE, key);

      const plaintext = Random.randBytes(10);
      const ciphertext = await primitive.encrypt(plaintext);

      assertObjectNotEquals(plaintext, ciphertext);
    }
  },

  async testGetPrimitive_fromKeyData() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keyDatas = await createTestSetOfKeyDatas();

    for (let key of keyDatas) {
      const /** HybridEncrypt */ primitive =
          await manager.getPrimitive(PRIMITIVE, key);

      const plaintext = Random.randBytes(10);
      const ciphertext = await primitive.encrypt(plaintext);

      assertObjectNotEquals(plaintext, ciphertext);
    }
  },

  testDoesSupport() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    assertTrue(manager.doesSupport(KEY_TYPE));
  },

  testGetKeyType() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    assertEquals(KEY_TYPE, manager.getKeyType());
  },

  testGetPrimitiveType() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    assertEquals(PRIMITIVE, manager.getPrimitiveType());
  },

  testGetVersion() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    assertEquals(VERSION, manager.getVersion());
  },
});

// Helper classes and functions
class ExceptionText {
  /** @return {string} */
  static notSupported() {
    return 'CustomError: This operation is not supported for public keys. ' +
        'Use EciesAeadHkdfPrivateKeyManager to generate new keys.';
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
  static missingParams() {
    return 'CustomError: Invalid public key - missing key params.';
  }

  /** @return {string} */
  static unknownPointFormat() {
    return 'CustomError: Invalid key params - unknown EC point format.';
  }

  /** @return {string} */
  static missingKemParams() {
    return 'CustomError: Invalid params - missing KEM params.';
  }

  /**
   * @param {string} templateTypeUrl
   * @return {string}
   */
  static unsupportedKeyTemplate(templateTypeUrl) {
    return 'CustomError: Invalid DEM params - ' + templateTypeUrl +
        ' template is not supported by ECIES AEAD HKDF.';
  }

  /** @return {string} */
  static missingXY() {
    return 'CustomError: Invalid public key - missing value of X or Y.';
  }

  /** @return {string} */
  static invalidSerializedKey() {
    return 'CustomError: Input cannot be parsed as ' + KEY_TYPE + ' key-proto.';
  }
}

/**
 * @param {PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {PbHashType=} opt_hashType (default: SHA256)
 *
 * @return {!PbEciesHkdfKemParams}
 */
const createKemParams = function(
    opt_curveType = PbEllipticCurveType.NIST_P256,
    opt_hashType = PbHashType.SHA256) {
  const kemParams = new PbEciesHkdfKemParams();

  kemParams.setCurveType(opt_curveType);
  kemParams.setHkdfHashType(opt_hashType);

  return kemParams;
};

/**
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 *
 * @return {!PbEciesAeadDemParams}
 */
const createDemParams = function(opt_keyTemplate) {
  if (!opt_keyTemplate) {
    opt_keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
  }

  const demParams = new PbEciesAeadDemParams();
  demParams.setAeadDem(opt_keyTemplate);

  return demParams;
};

/**
 * @param {PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @param {PbPointFormat=} opt_pointFormat (default: UNCOMPRESSED)
 *
 * @return {!PbEciesAeadHkdfParams}
 */
const createKeyParams = function(
    opt_curveType, opt_hashType, opt_keyTemplate,
    opt_pointFormat = PbPointFormat.UNCOMPRESSED) {
  const params = new PbEciesAeadHkdfParams();

  params.setKemParams(createKemParams(opt_curveType, opt_hashType));
  params.setDemParams(createDemParams(opt_keyTemplate));
  params.setEcPointFormat(opt_pointFormat);

  return params;
};


/**
 * @param {PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @param {PbPointFormat=} opt_pointFormat (default: UNCOMPRESSED)
 *
 * @return {!Promise<!PbEciesAeadHkdfPublicKey>}
 */
const createKey = async function(
    opt_curveType = PbEllipticCurveType.NIST_P256, opt_hashType,
    opt_keyTemplate, opt_pointFormat) {
  const curveSubtleType = Util.curveTypeProtoToSubtle(opt_curveType);
  const curveName = EllipticCurves.curveToString(curveSubtleType);

  const key = new PbEciesAeadHkdfPublicKey();
  key.setVersion(0);
  key.setParams(createKeyParams(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));


  const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
  const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey);
  key.setX(Bytes.fromBase64(publicKey['x'], /* opt_webSafe = */ true));
  key.setY(Bytes.fromBase64(publicKey['y'], /* opt_webSafe = */ true));

  return key;
};

/**
 * @param {!PbEciesAeadHkdfPublicKey} key
 *
 * @return {!PbKeyData}
 */
const createKeyDataFromKey = function(key) {
  const keyData = new PbKeyData();

  keyData.setTypeUrl(KEY_TYPE);
  keyData.setValue(key.serializeBinary());
  keyData.setKeyMaterialType(PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC);

  return keyData;
};

/**
 * @param {PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @param {PbPointFormat=} opt_pointFormat (default: UNCOMPRESSED)
 *
 * @return {!Promise<!PbKeyData>}
 */
const createKeyData = async function(
    opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat) {
  const key = await createKey(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat);
  return createKeyDataFromKey(key);
};


// Create set of keys with all possible predefined/supported parameters.
/** @return {!Promise<!Array<!PbEciesAeadHkdfPublicKey>>} */
const createTestSetOfKeys = async function() {
  const curveTypes = [
    PbEllipticCurveType.NIST_P256, PbEllipticCurveType.NIST_P384,
    PbEllipticCurveType.NIST_P521
  ];
  const hashTypes = [PbHashType.SHA1, PbHashType.SHA256, PbHashType.SHA512];
  const keyTemplates =
      [AeadKeyTemplates.aes128CtrHmacSha256(), AeadKeyTemplates.aes256Gcm()];
  const pointFormats = [PbPointFormat.UNCOMPRESSED];

  const /** Array<!PbEciesAeadHkdfPublicKey> */ keys = [];
  for (let curve of curveTypes) {
    for (let hkdfHash of hashTypes) {
      for (let keyTemplate of keyTemplates) {
        for (let pointFormat of pointFormats) {
          const key =
              await createKey(curve, hkdfHash, keyTemplate, pointFormat);
          keys.push(key);
        }
      }
    }
  }
  return keys;
};

// Create set of keyData protos with keys of all possible predefined/supported
// parameters.
/** @return {!Promise<!Array<!PbKeyData>>} */
const createTestSetOfKeyDatas = async function() {
  const keys = await createTestSetOfKeys();

  const /** Array<!PbKeyData> */ keyDatas = [];
  for (let key of keys) {
    const keyData = await createKeyDataFromKey(key);
    keyDatas.push(keyData);
  }

  return keyDatas;
};
