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
const {Mac} = goog.require('google3.third_party.tink.javascript.mac.internal.mac');
const {PublicKeyVerify} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_verify');
const Registry = goog.require('tink.Registry');
const Util = goog.require('tink.Util');
const {PbEcdsaParams, PbEcdsaPublicKey, PbEcdsaSignatureEncoding, PbEllipticCurveType, PbHashType, PbKeyData} = goog.require('google3.third_party.tink.javascript.internal.proto');

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
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.notSupported());
    }
  });

  it('new key data', function() {
    const manager = new EcdsaPublicKeyManager();

    try {
      manager.getKeyFactory().newKeyData(new Uint8Array(0));
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.notSupported());
    }
  });

  it('get primitive, unsupported primitive type', async function() {
    const manager = new EcdsaPublicKeyManager();
    const key = await createKey();

    try {
      await manager.getPrimitive(Mac, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unsupportedPrimitive());
    }
  });

  it('get primitive, unsupported key data type', async function() {
    const manager = new EcdsaPublicKeyManager();
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
    const manager = new EcdsaPublicKeyManager();
    let key = new PbEcdsaParams();

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
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
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.versionOutOfBounds());
    }
  });

  it('get primitive, missing params', async function() {
    const manager = new EcdsaPublicKeyManager();
    const key = (await createKey()).setParams(null);

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingParams());
    }
  });

  it('get primitive, invalid params', async function() {
    const manager = new EcdsaPublicKeyManager();
    const key = await createKey();

    // Unknown encoding.
    key.getParams().setEncoding(PbEcdsaSignatureEncoding.UNKNOWN_ENCODING);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownEncoding());
    }
    key.getParams().setEncoding(PbEcdsaSignatureEncoding.DER);

    // Unknown hash.
    key.getParams().setHashType(PbHashType.UNKNOWN_HASH);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownHash());
    }
    key.getParams().setHashType(PbHashType.SHA256);

    // Unknown curve.
    key.getParams().setCurve(PbEllipticCurveType.UNKNOWN_CURVE);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownCurve());
    }

    // Bad hash + curve combinations.
    key.getParams().setCurve(PbEllipticCurveType.NIST_P384);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256');
    }

    key.getParams().setCurve(PbEllipticCurveType.NIST_P521);
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-512 (because curve is P-521) but got SHA-256');
    }
  });

  it('get primitive, invalid key', async function() {
    const manager = new EcdsaPublicKeyManager();
    const key = await createKey();
    const x = key.getX();
    key.setX(new Uint8Array(0));

    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(ExceptionText.webCryptoErrors()).toContain(e.toString());
    }

    key.setX(x);
    key.setY(new Uint8Array(0));
    try {
      await manager.getPrimitive(PRIMITIVE, key);
      fail('An exception should be thrown.');
    } catch (e) {
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
      } catch (e) {
        expect(e.toString()).toBe(ExceptionText.invalidSerializedKey());
      }
    }
  });

  // tests for getting primitive from valid key/keyData
  it('get primitive, from key', async function() {
    const manager = new EcdsaPublicKeyManager();
    const keys = await createTestSetOfKeys();

    for (let key of keys) {
      await manager.getPrimitive(PRIMITIVE, key);
    }
  });

  it('get primitive, from key data', async function() {
    const manager = new EcdsaPublicKeyManager();
    const keyDatas = await createTestSetOfKeyDatas();

    for (let key of keyDatas) {
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
  /** @return {string} */
  static notSupported() {
    return 'SecurityException: This operation is not supported for public keys. ' +
        'Use EcdsaPrivateKeyManager to generate new keys.';
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
  static missingParams() {
    return 'SecurityException: Invalid public key - missing params.';
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

  /** @return {!Array<string>} */
  static webCryptoErrors() {
    return [
      'DataError',
      // Firefox
      'DataError: Data provided to an operation does not meet requirements',
    ];
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
