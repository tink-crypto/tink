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

const {AeadConfig} = goog.require('google3.third_party.tink.javascript.aead.aead_config');
const {AeadKeyTemplates} = goog.require('google3.third_party.tink.javascript.aead.aead_key_templates');
const Bytes = goog.require('google3.third_party.tink.javascript.subtle.bytes');
const EciesAeadHkdfPublicKeyManager = goog.require('tink.hybrid.EciesAeadHkdfPublicKeyManager');
const EllipticCurves = goog.require('google3.third_party.tink.javascript.subtle.elliptic_curves');
const {HybridEncrypt} = goog.require('google3.third_party.tink.javascript.hybrid.internal.hybrid_encrypt');
const {Mac} = goog.require('google3.third_party.tink.javascript.mac.internal.mac');
const Random = goog.require('google3.third_party.tink.javascript.subtle.random');
const Registry = goog.require('google3.third_party.tink.javascript.internal.registry');
const Util = goog.require('google3.third_party.tink.javascript.internal.util');
const {PbAesCtrKey, PbEciesAeadDemParams, PbEciesAeadHkdfParams, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyData, PbKeyTemplate, PbPointFormat} = goog.require('google3.third_party.tink.javascript.internal.proto');
const {assertExists} = goog.require('google3.third_party.tink.javascript.testing.internal.test_utils');

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
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.notSupported());
    }
  });

  it('new key data', function() {
    const manager = new EciesAeadHkdfPublicKeyManager();

    try {
      manager.getKeyFactory().newKeyData(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.notSupported());
    }
  });

  it('get primitive, unsupported primitive type', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = await createKey();

    try {
      await manager.getPrimitive(Mac, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedPrimitive());
    }
  });

  it('get primitive, unsupported key data type', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keyData =
        (await createKeyData()).setTypeUrl('unsupported_key_type_url');

    try {
      await manager.getPrimitive(PRIMITIVE, keyData);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.unsupportedKeyType(keyData.getTypeUrl()));
    }
  });

  it('get primitive, unsupported key type', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    let key = new PbAesCtrKey();

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
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
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.versionOutOfBounds());
    }
  });

  it('get primitive, missing params', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = (await createKey()).setParams(null);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingParams());
    }
  });

  it('get primitive, invalid params', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = await createKey();

    // unknown point format
    key.getParams().setEcPointFormat(PbPointFormat.UNKNOWN_FORMAT);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownPointFormat());
    }
    key.getParams().setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    key.getParams().setKemParams(null);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
    }
    key.getParams().setKemParams(createKemParams());

    // unsupported AEAD key template
    const typeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    key.getParams().getDemParams().getAeadDem().setTypeUrl(typeUrl);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedKeyTemplate(typeUrl));
    }
  });

  it('get primitive, invalid key', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const key = (await createKey()).setX('');

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingXY());
    }
    key.getParams().setEcPointFormat(PbPointFormat.UNCOMPRESSED);

    // missing KEM params
    key.getParams().setKemParams(null);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
    }
    key.getParams().setKemParams(createKemParams());

    // unsupported AEAD key template
    const typeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    key.getParams().getDemParams().getAeadDem().setTypeUrl(typeUrl);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
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
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
      }
    }
  });

  // tests for getting primitive from valid key/keyData
  it('get primitive, from key', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keys = await createTestSetOfKeys();

    for (let key of keys) {
      const /** !HybridEncrypt */ primitive =
          assertExists(await manager.getPrimitive(PRIMITIVE, key));

      const plaintext = Random.randBytes(10);
      const ciphertext = await primitive.encrypt(plaintext);

      expect(ciphertext).not.toEqual(plaintext);
    }
  });

  it('get primitive, from key data', async function() {
    const manager = new EciesAeadHkdfPublicKeyManager();
    const keyDatas = await createTestSetOfKeyDatas();

    for (let key of keyDatas) {
      const /** !HybridEncrypt */ primitive =
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
  /** @return {string} */
  static notSupported() {
    return 'SecurityException: This operation is not supported for public keys. ' +
        'Use EciesAeadHkdfPrivateKeyManager to generate new keys.';
  }

  /** @return {string} */
  static unsupportedPrimitive() {
    return 'SecurityException: Requested primitive type which is not supported by ' +
        'this key manager.';
  }

  /**
   * @param {string=} opt_requestedKeyType
   * @return {string}
   */
  static unsupportedKeyType(opt_requestedKeyType) {
    const prefix = 'SecurityException: Key type';
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
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        VERSION + '.';
  }

  /** @return {string} */
  static missingParams() {
    return 'SecurityException: Invalid public key - missing key params.';
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
  static missingXY() {
    return 'SecurityException: Invalid public key - missing value of X or Y.';
  }

  /** @return {string} */
  static invalidSerializedKey() {
    return 'SecurityException: Input cannot be parsed as ' + KEY_TYPE +
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
 *
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
 * @return {!Promise<!PbEciesAeadHkdfPublicKey>}
 */
const createKey = async function(
    opt_curveType = PbEllipticCurveType.NIST_P256, opt_hashType,
    opt_keyTemplate, opt_pointFormat) {
  const curveSubtleType = Util.curveTypeProtoToSubtle(opt_curveType);
  const curveName = EllipticCurves.curveToString(curveSubtleType);

  const key =
      new PbEciesAeadHkdfPublicKey().setVersion(0).setParams(createKeyParams(
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
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @param {!PbPointFormat=} opt_pointFormat (default: UNCOMPRESSED)
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

  const /** !Array<!PbEciesAeadHkdfPublicKey> */ keys = [];
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

  const /** !Array<!PbKeyData> */ keyDatas = [];
  for (let key of keys) {
    const keyData = await createKeyDataFromKey(key);
    keyDatas.push(keyData);
  }

  return keyDatas;
};
