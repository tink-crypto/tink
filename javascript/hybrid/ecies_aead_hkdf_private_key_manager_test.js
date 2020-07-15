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

const {AeadConfig} = goog.require('google3.third_party.tink.javascript.aead.aead_config');
const {AeadKeyTemplates} = goog.require('google3.third_party.tink.javascript.aead.aead_key_templates');
const EciesAeadHkdfPrivateKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPrivateKeyManager');
const EciesAeadHkdfPublicKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPublicKeyManager');
const {HybridDecrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_decrypt');
const {HybridEncrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_encrypt');
const KeyManager = goog.require('google3.third_party.tink.javascript.internal.key_manager');
const Random = goog.require('google3.third_party.tink.javascript.subtle.random');
const Registry = goog.require('google3.third_party.tink.javascript.internal.registry');
const {PbAesCtrKeyFormat, PbEciesAeadDemParams, PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyData, PbKeyTemplate, PbPointFormat} = goog.require('google3.third_party.tink.javascript.internal.proto');
const {assertExists, assertInstanceof} = goog.require('google3.third_party.tink.javascript.testing.internal.test_utils');

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
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
    }
  });

  it('new key, invalid serialized key format', async function() {
    const invalidSerializedKeyFormat = new Uint8Array(0);
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidSerializedKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
    }
  });

  it('new key, unsupported key format proto', async function() {
    const unsupportedKeyFormatProto = new PbAesCtrKeyFormat();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(unsupportedKeyFormatProto);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyFormat());
    }
  });

  it('new key, invalid format, missing params', async function() {
    const invalidFormat = new PbEciesAeadHkdfKeyFormat();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.invalidKeyFormatMissingParams());
    }
  });

  it('new key, invalid format, invalid params', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();

    // unknown point format
    const invalidFormat = createKeyFormat();
    invalidFormat.getParams().setEcPointFormat(PbPointFormat.UNKNOWN_FORMAT);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownPointFormat());
    }
    invalidFormat.getParams().setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    invalidFormat.getParams().setKemParams(null);
    try {
      await manager.getKeyFactory().newKey(invalidFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
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
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyTemplate(templateTypeUrl));
    }
  });

  it('new key, via key format', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    for (let keyFormat of keyFormats) {
      const key = /** @type{!PbEciesAeadHkdfPrivateKey} */ (
          await manager.getKeyFactory().newKey(keyFormat));

      expect(key.getPublicKey().getParams()).toEqual(keyFormat.getParams());
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
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKeyFormat());
        continue;
      }
    }
  });

  it('new key data, from valid key format', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const manager = new EciesAeadHkdfPrivateKeyManager();

    for (let keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = /** @type{!PbKeyData} */ (
          await manager.getKeyFactory().newKeyData(serializedKeyFormat));

      expect(keyData.getTypeUrl()).toBe(PRIVATE_KEY_TYPE);
      expect(keyData.getKeyMaterialType()).toBe(PRIVATE_KEY_MATERIAL_TYPE);

      const key =
          PbEciesAeadHkdfPrivateKey.deserializeBinary(keyData.getValue());
      expect(key.getPublicKey().getParams()).toEqual(keyFormat.getParams());
      // The keys are tested more in tests for getPrimitive method below, where
      // the primitive based on the created key is tested.
    }
  });

  it('get public key data, invalid private key serialization', function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();

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
    const manager = new EciesAeadHkdfPrivateKeyManager();

    const privateKey = /** @type{!PbEciesAeadHkdfPrivateKey} */ (
        await manager.getKeyFactory().newKey(keyFormat));
    const factory =
        /** @type {!KeyManager.PrivateKeyFactory} */ (manager.getKeyFactory());
    const publicKeyData =
        factory.getPublicKeyData(privateKey.serializeBinary());

    expect(publicKeyData.getTypeUrl()).toBe(PUBLIC_KEY_TYPE);
    expect(publicKeyData.getKeyMaterialType()).toBe(PUBLIC_KEY_MATERIAL_TYPE);
    const publicKey =
        PbEciesAeadHkdfPublicKey.deserializeBinary(publicKeyData.getValue());
    expect(publicKey.getVersion())
        .toEqual(privateKey.getPublicKey().getVersion());
    expect(publicKey.getParams())
        .toEqual(privateKey.getPublicKey().getParams());
    expect(publicKey.getX()).toEqual(privateKey.getPublicKey().getX());
    expect(publicKey.getY()).toEqual(privateKey.getPublicKey().getY());
  });

  it('get primitive, unsupported primitive type', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    const keyFormat = createKeyFormat();
    const key = await manager.getKeyFactory().newKey(keyFormat);

    try {
      await manager.getPrimitive(HybridEncrypt, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedPrimitive());
    }
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
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyType(keyData.getTypeUrl()));
    }
  });

  it('get primitive, unsupported key type', async function() {
    const manager = new EciesAeadHkdfPrivateKeyManager();
    let key = new PbEciesAeadHkdfPublicKey();

    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
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
    } catch (e) {
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
    key.getPublicKey().getParams().setKemParams(null);
    try {
      await manager.getPrimitive(PRIVATE_KEY_MANAGER_PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
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
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
      }
    }
  });

  it('get primitive, from key', async function() {
    const keyFormats = createTestSetOfKeyFormats();
    const privateKeyManager = new EciesAeadHkdfPrivateKeyManager();
    const publicKeyManager = new EciesAeadHkdfPublicKeyManager();

    for (let keyFormat of keyFormats) {
      const key = assertInstanceof(
          await privateKeyManager.getKeyFactory().newKey(keyFormat),
          PbEciesAeadHkdfPrivateKey);

      const /** !HybridEncrypt */ hybridEncrypt =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, assertExists(key.getPublicKey())));
      const /** !HybridDecrypt */ hybridDecrypt =
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

    for (let keyFormat of keyFormats) {
      const serializedKeyFormat = keyFormat.serializeBinary();
      const keyData = await privateKeyManager.getKeyFactory().newKeyData(
          serializedKeyFormat);
      const factory = /** @type {!KeyManager.PrivateKeyFactory} */ (
          privateKeyManager.getKeyFactory());
      const publicKeyData = factory.getPublicKeyData(keyData.getValue_asU8());

      const /** !HybridEncrypt */ hybridEncrypt =
          assertExists(await publicKeyManager.getPrimitive(
              PUBLIC_KEY_MANAGER_PRIMITIVE, publicKeyData));
      const /** !HybridDecrypt */ hybridDecrypt =
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
  static versionOutOfBounds() {
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  /** @return {string} */
  static invalidKeyFormatMissingParams() {
    return 'SecurityException: Invalid key format - missing key params.';
  }

  /** @return {string} */
  static unknownPointFormat() {
    return 'SecurityException: Invalid key params - unknown EC point format.';
  }

  /** @return {string} */
  static missingKemParams() {
    return 'SecurityException: Invalid params - missing KEM params.';
  }

  /**
   * @param {string} templateTypeUrl
   * @return {string}
   */
  static unsupportedKeyTemplate(templateTypeUrl) {
    return 'SecurityException: Invalid DEM params - ' + templateTypeUrl +
        ' template is not supported by ECIES AEAD HKDF.';
  }

  /** @return {string} */
  static invalidSerializedKey() {
    return 'SecurityException: Input cannot be parsed as ' + PRIVATE_KEY_TYPE +
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
