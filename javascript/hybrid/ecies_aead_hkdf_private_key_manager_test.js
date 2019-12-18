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

goog.module('tink.hybrid.EciesAeadHkdfPrivateKeyManagerTest');
goog.setTestOnly('tink.hybrid.EciesAeadHkdfPrivateKeyManagerTest');

const AeadConfig = goog.require('tink.aead.AeadConfig');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const EciesAeadHkdfPrivateKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPrivateKeyManager');
const EciesAeadHkdfPublicKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPublicKeyManager');
const HybridDecrypt = goog.require('tink.HybridDecrypt');
const HybridEncrypt = goog.require('tink.HybridEncrypt');
const KeyManager = goog.require('tink.KeyManager');
const PbAesCtrKeyFormat = goog.require('proto.google.crypto.tink.AesCtrKeyFormat');
const PbEciesAeadDemParams = goog.require('proto.google.crypto.tink.EciesAeadDemParams');
const PbEciesAeadHkdfKeyFormat = goog.require('proto.google.crypto.tink.EciesAeadHkdfKeyFormat');
const PbEciesAeadHkdfParams = goog.require('proto.google.crypto.tink.EciesAeadHkdfParams');
const PbEciesAeadHkdfPrivateKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPrivateKey');
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
const asserts = goog.require('goog.asserts');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');

const PRIVATE_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey';
const PRIVATE_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PRIVATE;
const VERSION = 0;
const PRIVATE_KEY_MANAGER_PRIMITIVE = HybridDecrypt;

const PUBLIC_KEY_TYPE =
    'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey';
const PUBLIC_KEY_MATERIAL_TYPE = PbKeyData.KeyMaterialType.ASYMMETRIC_PUBLIC;
const PUBLIC_KEY_MANAGER_PRIMITIVE = HybridEncrypt;

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

  async testNewKey_emptyKeyFormat() {
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.invalidSerializedKeyFormat(), e.toString());
    }
  },

  async testNewKey_invalidSerializedKeyFormat() {
    const invalidSerializedKeyFormat = new Uint8Array(0);
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidSerializedKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.invalidSerializedKeyFormat(), e.toString());
    }
  },

  async testNewKey_unsupportedKeyFormatProto() {
    const unsupportedKeyFormatProto = new PbAesCtrKeyFormat();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(unsupportedKeyFormatProto);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyFormat(), e.toString());
    }
  },

  async testNewKey_invalidFormat_missingParams() {
    const invalidFormat = new PbEciesAeadHkdfKeyFormat();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.invalidKeyFormatMissingParams(), e.toString());
    }
  },

  async testNewKey_invalidFormat_invalidParams() {
    const manager = new EciesAeadHkdfPrivateKeyManager();

    // unknown point format
    const invalidFormat = createKeyFormat();
    invalidFormat.getParams().setEcPointFormat(PbPointFormat.UNKNOWN_FORMAT);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownPointFormat(), e.toString());
    }
    invalidFormat.getParams().setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    invalidFormat.getParams().setKemParams(null);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingKemParams(), e.toString());
    }
    invalidFormat.getParams().setKemParams(createKemParams());

    // unsupported AEAD template
    const templateTypeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    invalidFormat.getParams().getDemParams().getAeadDem().setTypeUrl(
        templateTypeUrl);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.unsupportedKeyTemplate(templateTypeUrl), e.toString());
    }
  },

  async testNewKey_viaKeyFormat() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    for (let keyFormat of keyFormats) {
      const key = /** @type{!PbEciesAeadHkdfPrivateKey} */ (
          await manager.getKeyFactory().newKey(keyFormat));

      assertObjectEquals(keyFormat.getParams(), key.getPublicKey().getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  },

  async testNewKeyData_invalidSerializedKeyFormat() {
    const serializedKeyFormats = [new Uint8Array(1), new Uint8Array(0)];
    const manager = new EciesAeadHkdfPrivateKeyManager();

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
    const manager = new EciesAeadHkdfPrivateKeyManager();

    for (let keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = /** @type{!PbKeyData} */ (
          await manager.getKeyFactory().newKeyData(serializedKeyFormat));

      assertEquals(PRIVATE_KEY_TYPE, keyData.getTypeUrl());
      assertEquals(PRIVATE_KEY_MATERIAL_TYPE, keyData.getKeyMaterialType());

      const key =
          PbEciesAeadHkdfPrivateKey.deserializeBinary(keyData.getValue());
      assertObjectEquals(keyFormat.getParams(), key.getPublicKey().getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  },

  testGetPublicKeyData_invalidPrivateKeySerialization() {
    const manager = new EciesAeadHkdfPrivateKeyManager();

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
    const manager = new EciesAeadHkdfPrivateKeyManager();

    const privateKey = /** @type{!PbEciesAeadHkdfPrivateKey} */ (
        await manager.getKeyFactory().newKey(keyFormat));
    const factory =
        /** @type {!KeyManager.PrivateKeyFactory} */ (manager.getKeyFactory());
    const publicKeyData =
        factory.getPublicKeyData(privateKey.serializeBinary());

    assertEquals(PUBLIC_KEY_TYPE, publicKeyData.getTypeUrl());
    assertEquals(PUBLIC_KEY_MATERIAL_TYPE, publicKeyData.getKeyMaterialType());
    const publicKey =
        PbEciesAeadHkdfPublicKey.deserializeBinary(publicKeyData.getValue());
    assertObjectEquals(
        privateKey.getPublicKey().getVersion(), publicKey.getVersion());
    assertObjectEquals(
        privateKey.getPublicKey().getParams(), publicKey.getParams());
    assertObjectEquals(privateKey.getPublicKey().getX(), publicKey.getX());
    assertObjectEquals(privateKey.getPublicKey().getY(), publicKey.getY());
  },

  async testGetPrimitive_unsupportedPrimitiveType() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const key = await manager.getKeyFactory().newKey(keyFormat);

    try {
      await manager.getPrimitive(HybridEncrypt, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedPrimitive(), e.toString());
    }
  },

  async testGetPrimitive_unsupportedKeyDataType() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
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
    const manager = new EciesAeadHkdfPrivateKeyManager();
    let key = new PbEciesAeadHkdfPublicKey();

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unsupportedKeyType(), e.toString());
    }
  },

  async testGetPrimitive_highVersion() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const version = manager.getVersion() + 1;
    const keyFormat = createKeyFormat();
    const key = asserts
                    .assertInstanceof(
                        await manager.getKeyFactory().newKey(keyFormat),
                        PbEciesAeadHkdfPrivateKey)
                    .setVersion(version);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.versionOutOfBounds(), e.toString());
    }
  },


  async testGetPrimitive_invalidParams() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const key = asserts.assertInstanceof(
        await manager.getKeyFactory().newKey(keyFormat),
        PbEciesAeadHkdfPrivateKey);

    // missing KEM params
    key.getPublicKey().getParams().setKemParams(null);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingKemParams(), e.toString());
    }
    key.getPublicKey().getParams().setKemParams(createKemParams());

    // unsupported AEAD key template type URL
    const templateTypeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    key.getPublicKey().getParams().getDemParams().getAeadDem().setTypeUrl(
        templateTypeUrl);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.unsupportedKeyTemplate(templateTypeUrl), e.toString());
    }
  },

  async testGetPrimitive_invalidSerializedKey() {
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
      } catch (e) {
        assertEquals(ExceptionText.invalidSerializedKey(), e.toString());
      }
    }
  },

  async testGetPrimitive_fromKey() {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new EciesAeadHkdfPrivateKeyManager();
    const publicKeyManager = new EciesAeadHkdfPublicKeyManager();

    for (let keyFormat of keyFormats) {
      const key = asserts.assertInstanceof(
          await privateKeyManager.getKeyFactory().newKey(keyFormat),
          PbEciesAeadHkdfPrivateKey);

      const /** !HybridEncrypt */ hybridEncrypt =
          asserts.assert(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE,
              asserts.assert(key.getPublicKey())));
      const /** !HybridDecrypt */ hybridDecrypt =
          asserts.assert(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, key));

      const plaintext = Random.randBytes(10);
      const ciphertext = await hybridEncrypt.encrypt(plaintext);
      const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

      assertObjectEquals(plaintext, decryptedCiphertext);
    }
  },

  async testGetPrimitive_fromKeyData() {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new EciesAeadHkdfPrivateKeyManager();
    const publicKeyManager = new EciesAeadHkdfPublicKeyManager();

    for (let keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = await privateKeyManager.getKeyFactory().newKeyData(
          serializedKeyFormat);
      const factory = /** @type {!KeyManager.PrivateKeyFactory} */ (
          privateKeyManager.getKeyFactory());
      const publicKeyData = factory.getPublicKeyData(keyData.getValue_asU8());

      const /** !HybridEncrypt */ hybridEncrypt =
          asserts.assert(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, publicKeyData));
      const /** !HybridDecrypt */ hybridDecrypt =
          asserts.assert(await privateKeyManager.getPrimitive(
              PRIVATE_KEY_MANAGER_PRIMITIVE, keyData));

      const plaintext = Random.randBytes(10);
      const ciphertext = await hybridEncrypt.encrypt(plaintext);
      const decryptedCiphertext = await hybridDecrypt.decrypt(ciphertext);

      assertObjectEquals(plaintext, decryptedCiphertext);
    }
  },

  testDoesSupport() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    assertTrue(manager.doesSupport(PRIVATE_KEY_TYPE));
  },

  testGetKeyType() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    assertEquals(PRIVATE_KEY_TYPE, manager.getKeyType());
  },

  testGetPrimitiveType() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    assertEquals(PRIVATE_KEY_MANAGER_PRIMITIVE, manager.getPrimitiveType());
  },

  testGetVersion() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
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
  static versionOutOfBounds() {
    return 'CustomError: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  /** @return {string} */
  static invalidKeyFormatMissingParams() {
    return 'CustomError: Invalid key format - missing key params.';
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
  static invalidSerializedKey() {
    return 'CustomError: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
        ' key-proto.';
  }
}

/**
 * @param {!PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {!PbHashType=} opt_hashType (default: SHA256)
 *
 * @return {!PbEciesHkdfKemParams}
 */
const createKemParams = function(
    opt_curveType = PbEllipticCurveType.NIST_P256,
    opt_hashType = PbHashType.SHA256) {
  const kemParams = new PbEciesHkdfKemParams()
                        .setCurveType(opt_curveType)
                        .setHkdfHashType(opt_hashType);

  return kemParams;
};

/**
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @return {!PbEciesAeadDemParams}
 */
const createDemParams = function(opt_keyTemplate) {
  if (!opt_keyTemplate) {
    opt_keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
  }

  const demParams = new PbEciesAeadDemParams().setAeadDem(opt_keyTemplate);

  return demParams;
};

/**
 * @param {!PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {!PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @param {!PbPointFormat=} opt_pointFormat (default: UNCOMPRESSED)
 *
 * @return {!PbEciesAeadHkdfParams}
 */
const createKeyParams = function(
    opt_curveType, opt_hashType, opt_keyTemplate,
    opt_pointFormat = PbPointFormat.UNCOMPRESSED) {
  const params = new PbEciesAeadHkdfParams()
                     .setKemParams(createKemParams(opt_curveType, opt_hashType))
                     .setDemParams(createDemParams(opt_keyTemplate))
                     .setEcPointFormat(opt_pointFormat);

  return params;
};

/**
 * @param {!PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {!PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @param {!PbPointFormat=} opt_pointFormat (default: UNCOMPRESSED)
 *
 * @return {!PbEciesAeadHkdfKeyFormat}
 */
const createKeyFormat = function(
    opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat) {
  const keyFormat = new PbEciesAeadHkdfKeyFormat().setParams(createKeyParams(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));
  return keyFormat;
};

// Create set of key formats with all possible predefined/supported parameters.
/** @return {!Array<!PbEciesAeadHkdfKeyFormat>} */
const createTestSetOfKeyFormats = function() {
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

  const /** !Array<!PbEciesAeadHkdfKeyFormat> */ keyFormats = [];
  for (let curve of curveTypes) {
    for (let hkdfHash of hashTypes) {
      for (let keyTemplate of keyTemplates) {
        for (let pointFormat of pointFormats) {
          const keyFormat =
              createKeyFormat(curve, hkdfHash, keyTemplate, pointFormat);
          keyFormats.push(keyFormat);
        }
      }
    }
  }
  return keyFormats;
};
