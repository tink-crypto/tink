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

goog.module('tink.hybrid.EciesAeadHkdfValidatorsTest');
goog.setTestOnly('tink.hybrid.EciesAeadHkdfValidatorsTest');

const {AeadKeyTemplates} = goog.require('google3.third_party.tink.javascript.aead.aead_key_templates');
const Bytes = goog.require('google3.third_party.tink.javascript.subtle.bytes');
const EciesAeadHkdfValidators = goog.require('tink.hybrid.EciesAeadHkdfValidators');
const EllipticCurves = goog.require('google3.third_party.tink.javascript.subtle.elliptic_curves');
const Util = goog.require('google3.third_party.tink.javascript.internal.util');
const {PbEciesAeadDemParams, PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyTemplate, PbPointFormat} = goog.require('google3.third_party.tink.javascript.internal.proto');
const {assertExists} = goog.require('google3.third_party.tink.javascript.testing.internal.test_utils');


describe('ecies aead hkdf validators test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('validate params, missing kem params', function() {
    const invalidParams = createParams().setKemParams(null);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
    }
  });

  it('validate params, invalid kem params, unknown hash type', function() {
    const invalidParams = createParams();
    invalidParams.getKemParams().setHkdfHashType(PbHashType.UNKNOWN_HASH);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownHashType());
    }
  });

  it('validate params, invalid kem params, unknown curve type', function() {
    const invalidParams = createParams();
    invalidParams.getKemParams().setCurveType(
        PbEllipticCurveType.UNKNOWN_CURVE);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownCurveType());
    }
  });

  it('validate params, missing dem params', function() {
    const invalidParams = createParams().setDemParams(null);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingDemParams());
    }
  });

  it('validate params, invalid dem params, missing aead template', function() {
    const invalidParams = createParams();
    invalidParams.getDemParams().setAeadDem(null);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingAeadTemplate());
    }
  });

  it('validate params, invalid dem params, unsupported aead template',
     function() {
       const unsupportedTypeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
       const invalidParams = createParams();
       invalidParams.getDemParams().getAeadDem().setTypeUrl(unsupportedTypeUrl);

       try {
         EciesAeadHkdfValidators.validateParams(invalidParams);
         fail('An exception should be thrown.');
       } catch (e) {
         expect(e.toString())
             .toBe(ExceptionText.unsupportedKeyTemplate(unsupportedTypeUrl));
       }
     });

  it('validate params, unknown point format', function() {
    const invalidParams =
        createParams().setEcPointFormat(PbPointFormat.UNKNOWN_FORMAT);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownPointFormat());
    }
  });

  it('validate params, different valid values', function() {
    const curves = Object.keys(PbEllipticCurveType);
    const hashTypes = Object.keys(PbHashType);
    const keyTemplates =
        [AeadKeyTemplates.aes128CtrHmacSha256(), AeadKeyTemplates.aes128Gcm()];
    const pointFormats = Object.keys(PbPointFormat);

    for (let curveId of curves) {
      const curve = PbEllipticCurveType[curveId];
      if (curve === PbEllipticCurveType.UNKNOWN_CURVE ||
          curve === PbEllipticCurveType.CURVE25519) {
        continue;
      }
      for (let hashTypeId of hashTypes) {
        const hashType = PbHashType[hashTypeId];
        if (hashType === PbHashType.UNKNOWN_HASH) {
          continue;
        }
        for (let keyTemplate of keyTemplates) {
          for (let pointFormatId of pointFormats) {
            const pointFormat = PbPointFormat[pointFormatId];
            if (pointFormat === PbPointFormat.UNKNOWN_FORMAT) {
              continue;
            }
            const params =
                createParams(curve, hashType, keyTemplate, pointFormat);
            EciesAeadHkdfValidators.validateParams(params);
          }
        }
      }
    }
  });

  it('validate key format, missing params', function() {
    const invalidKeyFormat = new PbEciesAeadHkdfKeyFormat();

    try {
      EciesAeadHkdfValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingFormatParams());
    }
  });

  it('validate key format, invalid params', function() {
    const invalidKeyFormat =
        new PbEciesAeadHkdfKeyFormat().setParams(createParams());

    // Check that also params were checked.
    // Test missing DEM params.
    invalidKeyFormat.getParams().setDemParams(null);
    try {
      EciesAeadHkdfValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingDemParams());
    }
    invalidKeyFormat.getParams().setDemParams(createDemParams());

    // Test UNKNOWN_HASH in KEM params.
    invalidKeyFormat.getParams().getKemParams().setHkdfHashType(
        PbHashType.UNKNOWN_HASH);
    try {
      EciesAeadHkdfValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownHashType());
    }
  });

  it('validate public key, missing params', function() {
    const invalidPublicKey = new PbEciesAeadHkdfPublicKey();

    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingKeyParams());
    }
  });

  it('validate public key, missing values x y', function() {
    const invalidPublicKey =
        new PbEciesAeadHkdfPublicKey().setParams(createParams());

    // Both X and Y are set to empty.
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingXY());
    }

    // The key with only Y set to empty is also invalid.
    invalidPublicKey.setX(new Uint8Array(10));
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingXY());
    }

    // The key with only X set to empty is also invalid.
    invalidPublicKey.setY(new Uint8Array(10));
    invalidPublicKey.setX(new Uint8Array(0));
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingXY());
    }
  });

  it('validate public key, invalid params', async function() {
    const invalidPublicKey = await createPublicKey();

    // Check that also params were checked.
    // Test missing DEM params.
    invalidPublicKey.getParams().setDemParams(null);
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingDemParams());
    }
    invalidPublicKey.getParams().setDemParams(createDemParams());

    // Test UNKNOWN_HASH in KEM params.
    invalidPublicKey.getParams().getKemParams().setHkdfHashType(
        PbHashType.UNKNOWN_HASH);
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.unknownHashType());
    }
  });

  it('validate public key, version out of bounds', async function() {
    const managerVersion = 0;
    const invalidPublicKey = (await createPublicKey()).setVersion(1);
    try {
      EciesAeadHkdfValidators.validatePublicKey(
          invalidPublicKey, managerVersion);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.versionOutOfBounds(managerVersion));
    }
  });

  it('validate private key, missing public key', async function() {
    const invalidPrivateKey = (await createPrivateKey()).setPublicKey(null);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(invalidPrivateKey, 0, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingPublicKey());
    }
  });

  it('validate private key, invalid public key', async function() {
    const invalidPrivateKey = await createPrivateKey();
    invalidPrivateKey.getPublicKey().setParams(null);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(invalidPrivateKey, 0, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString()).toBe(ExceptionText.missingKeyParams());
    }
  });

  it('validate private key, should work', async function() {
    const privateKey = await createPrivateKey();
    EciesAeadHkdfValidators.validatePrivateKey(privateKey, 0, 0);
  });

  it('validate private key, version out of bounds', async function() {
    const managerVersion = 0;
    const invalidPrivateKey = (await createPrivateKey()).setVersion(1);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(
          invalidPrivateKey, managerVersion, managerVersion);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe(ExceptionText.versionOutOfBounds(managerVersion));
    }
  });
});

// Helper classes and functions
class ExceptionText {
  /** @return {string} */
  static missingFormatParams() {
    return 'SecurityException: Invalid key format - missing key params.';
  }

  /** @return {string} */
  static missingKeyParams() {
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

  /** @return {string} */
  static unknownHashType() {
    return 'SecurityException: Invalid KEM params - unknown hash type.';
  }

  /** @return {string} */
  static unknownCurveType() {
    return 'SecurityException: Invalid KEM params - unknown curve type.';
  }

  /** @return {string} */
  static missingDemParams() {
    return 'SecurityException: Invalid params - missing DEM params.';
  }

  /** @return {string} */
  static missingAeadTemplate() {
    return 'SecurityException: Invalid DEM params - missing AEAD key template.';
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
  static missingPublicKey() {
    return 'SecurityException: Invalid private key - missing public key information.';
  }

  /** @return {string} */
  static missingPrivateKeyValue() {
    return 'SecurityException: Invalid private key - missing private key value.';
  }

  /**
   * @param {number} version
   * @return {string}
   */
  static versionOutOfBounds(version) {
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        version + '.';
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
const createParams = function(
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
 * @return {!Promise<!PbEciesAeadHkdfPrivateKey>}
 */
const createPrivateKey = async function(
    opt_curveType = PbEllipticCurveType.NIST_P256, opt_hashType,
    opt_keyTemplate, opt_pointFormat) {
  const curveSubtleType = Util.curveTypeProtoToSubtle(opt_curveType);
  const curveName = EllipticCurves.curveToString(curveSubtleType);

  const publicKeyProto =
      new PbEciesAeadHkdfPublicKey().setVersion(0).setParams(createParams(
          opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));
  const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
  const jsonPublicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey);
  publicKeyProto.setX(
      Bytes.fromBase64(jsonPublicKey['x'], /* opt_webSafe = */ true));
  publicKeyProto.setY(
      Bytes.fromBase64(jsonPublicKey['y'], /* opt_webSafe = */ true));


  const privateKeyProto =
      new PbEciesAeadHkdfPrivateKey().setVersion(0).setPublicKey(
          publicKeyProto);
  const jsonPrivateKey =
      await EllipticCurves.exportCryptoKey(keyPair.privateKey);
  privateKeyProto.setKeyValue(
      Bytes.fromBase64(jsonPrivateKey['d'], /* opt_webSafe = */ true));

  return privateKeyProto;
};

/**
 * @param {!PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {!PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @param {!PbPointFormat=} opt_pointFormat (default: UNCOMPRESSED)
 *
 * @return {!Promise<!PbEciesAeadHkdfPublicKey>}
 */
const createPublicKey = async function(
    opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat) {
  const key = await createPrivateKey(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat);
  return assertExists(key.getPublicKey());
};
