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

const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const Bytes = goog.require('tink.subtle.Bytes');
const EciesAeadHkdfValidators = goog.require('tink.hybrid.EciesAeadHkdfValidators');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const PbEciesAeadDemParams = goog.require('proto.google.crypto.tink.EciesAeadDemParams');
const PbEciesAeadHkdfKeyFormat = goog.require('proto.google.crypto.tink.EciesAeadHkdfKeyFormat');
const PbEciesAeadHkdfParams = goog.require('proto.google.crypto.tink.EciesAeadHkdfParams');
const PbEciesAeadHkdfPrivateKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPrivateKey');
const PbEciesAeadHkdfPublicKey = goog.require('proto.google.crypto.tink.EciesAeadHkdfPublicKey');
const PbEciesHkdfKemParams = goog.require('proto.google.crypto.tink.EciesHkdfKemParams');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbKeyTemplate = goog.require('proto.google.crypto.tink.KeyTemplate');
const PbPointFormat = goog.require('proto.google.crypto.tink.EcPointFormat');
const TestCase = goog.require('goog.testing.TestCase');
const Util = goog.require('tink.Util');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');


testSuite({
  shouldRunTests() {
    return !userAgent.EDGE;  // b/120286783
  },

  setUp() {
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  testValidateParams_missingKemParams() {
    const invalidParams = createParams();
    invalidParams.setKemParams(null);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingKemParams(), e.toString());
    }
  },

  testValidateParams_invalidKemParams_unknownHashType() {
    const invalidParams = createParams();
    invalidParams.getKemParams().setHkdfHashType(PbHashType.UNKNOWN_HASH);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownHashType(), e.toString());
    }
  },

  testValidateParams_invalidKemParams_unknownCurveType() {
    const invalidParams = createParams();
    invalidParams.getKemParams().setCurveType(
        PbEllipticCurveType.UNKNOWN_CURVE);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownCurveType(), e.toString());
    }
  },

  testValidateParams_missingDemParams() {
    const invalidParams = createParams();
    invalidParams.setDemParams(null);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingDemParams(), e.toString());
    }
  },

  testValidateParams_invalidDemParams_missingAeadTemplate() {
    const invalidParams = createParams();
    invalidParams.getDemParams().setAeadDem(null);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingAeadTemplate(), e.toString());
    }
  },

  testValidateParams_invalidDemParams_unsupportedAeadTemplate() {
    const unsupportedTypeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
    const invalidParams = createParams();
    invalidParams.getDemParams().getAeadDem().setTypeUrl(unsupportedTypeUrl);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.unsupportedKeyTemplate(unsupportedTypeUrl),
          e.toString());
    }
  },

  testValidateParams_unknownPointFormat() {
    const invalidParams = createParams();
    invalidParams.setEcPointFormat(PbPointFormat.UNKNOWN_FORMAT);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownPointFormat(), e.toString());
    }
  },

  testValidateParams_differentValidValues() {
    const curves = Object.keys(PbEllipticCurveType);
    const hashTypes = Object.keys(PbHashType);
    const keyTemplates =
        [AeadKeyTemplates.aes128CtrHmacSha256(), AeadKeyTemplates.aes128Gcm()];
    const pointFormats = Object.keys(PbPointFormat);

    for (let curveId of curves) {
      const curve = PbEllipticCurveType[curveId];
      if (curve === PbEllipticCurveType.UNKNOWN_CURVE) {
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
  },

  testValidateKeyFormat_missingParams() {
    const invalidKeyFormat = new PbEciesAeadHkdfKeyFormat();

    try {
      EciesAeadHkdfValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingFormatParams(), e.toString());
    }
  },

  testValidateKeyFormat_invalidParams() {
    const invalidKeyFormat = new PbEciesAeadHkdfKeyFormat();
    invalidKeyFormat.setParams(createParams());

    // Check that also params were checked.
    // Test missing DEM params.
    invalidKeyFormat.getParams().setDemParams(null);
    try {
      EciesAeadHkdfValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingDemParams(), e.toString());
    }
    invalidKeyFormat.getParams().setDemParams(createDemParams());

    // Test UNKNOWN_HASH in KEM params.
    invalidKeyFormat.getParams().getKemParams().setHkdfHashType(
        PbHashType.UNKNOWN_HASH);
    try {
      EciesAeadHkdfValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownHashType(), e.toString());
    }
  },

  testValidatePublicKey_missingParams() {
    const invalidPublicKey = new PbEciesAeadHkdfPublicKey();

    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingKeyParams(), e.toString());
    }
  },

  testValidatePublicKey_missingValuesXY() {
    const invalidPublicKey = new PbEciesAeadHkdfPublicKey();
    invalidPublicKey.setParams(createParams());

    // Both X and Y are set to null.
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingXY(), e.toString());
    }

    // The key with only Y set to null is also invalid.
    invalidPublicKey.setX(new Uint8Array(10));
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingXY(), e.toString());
    }

    // The key with only X set to null is also invalid.
    invalidPublicKey.setY(new Uint8Array(10));
    invalidPublicKey.setX(null);
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingXY(), e.toString());
    }
  },

  async testValidatePublicKey_invalidParams() {
    const invalidPublicKey = await createPublicKey();

    // Check that also params were checked.
    // Test missing DEM params.
    invalidPublicKey.getParams().setDemParams(null);
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingDemParams(), e.toString());
    }
    invalidPublicKey.getParams().setDemParams(createDemParams());

    // Test UNKNOWN_HASH in KEM params.
    invalidPublicKey.getParams().getKemParams().setHkdfHashType(
        PbHashType.UNKNOWN_HASH);
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.unknownHashType(), e.toString());
    }
  },

  async testValidatePublicKey_versionOutOfBounds() {
    const managerVersion = 0;
    const invalidPublicKey = await createPublicKey();

    invalidPublicKey.setVersion(1);
    try {
      EciesAeadHkdfValidators.validatePublicKey(
          invalidPublicKey, managerVersion);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.versionOutOfBounds(managerVersion), e.toString());
    }
  },

  async testValidatePrivateKey_missingPublicKey() {
    const invalidPrivateKey = await createPrivateKey();
    invalidPrivateKey.setPublicKey(null);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(invalidPrivateKey, 0, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingPublicKey(), e.toString());
    }
  },

  async testValidatePrivateKey_invalidPublicKey() {
    const invalidPrivateKey = await createPrivateKey();
    invalidPrivateKey.getPublicKey().setParams(null);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(invalidPrivateKey, 0, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingKeyParams(), e.toString());
    }
  },

  async testValidatePrivateKey_missingPrivateKeyValue() {
    const invalidPrivateKey = await createPrivateKey();
    invalidPrivateKey.setKeyValue(null);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(invalidPrivateKey, 0, 0);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.missingPrivateKeyValue(), e.toString());
    }
  },

  async testValidatePrivateKey_shouldWork() {
    const privateKey = await createPrivateKey();
    EciesAeadHkdfValidators.validatePrivateKey(privateKey, 0, 0);
  },

  async testValidatePrivateKey_versionOutOfBounds() {
    const managerVersion = 0;
    const invalidPrivateKey = await createPrivateKey();

    invalidPrivateKey.setVersion(1);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(
          invalidPrivateKey, managerVersion, managerVersion);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.versionOutOfBounds(managerVersion), e.toString());
    }
  },
});

// Helper classes and functions
class ExceptionText {
  /** @return {string} */
  static missingFormatParams() {
    return 'CustomError: Invalid key format - missing key params.';
  }

  /** @return {string} */
  static missingKeyParams() {
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

  /** @return {string} */
  static unknownHashType() {
    return 'CustomError: Invalid KEM params - unknown hash type.';
  }

  /** @return {string} */
  static unknownCurveType() {
    return 'CustomError: Invalid KEM params - unknown curve type.';
  }

  /** @return {string} */
  static missingDemParams() {
    return 'CustomError: Invalid params - missing DEM params.';
  }

  /** @return {string} */
  static missingAeadTemplate() {
    return 'CustomError: Invalid DEM params - missing AEAD key template.';
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
  static missingPublicKey() {
    return 'CustomError: Invalid private key - missing public key information.';
  }

  /** @return {string} */
  static missingPrivateKeyValue() {
    return 'CustomError: Invalid private key - missing private key value.';
  }

  /**
   * @param {number} version
   * @return {string}
   */
  static versionOutOfBounds(version) {
    return 'CustomError: Version is out of bound, must be between 0 and ' +
        version + '.';
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
const createParams = function(
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
 * @return {!Promise<!PbEciesAeadHkdfPrivateKey>}
 */
const createPrivateKey = async function(
    opt_curveType = PbEllipticCurveType.NIST_P256, opt_hashType,
    opt_keyTemplate, opt_pointFormat) {
  const curveSubtleType = Util.curveTypeProtoToSubtle(opt_curveType);
  const curveName = EllipticCurves.curveToString(curveSubtleType);

  const publicKeyProto = new PbEciesAeadHkdfPublicKey();
  publicKeyProto.setVersion(0);
  publicKeyProto.setParams(createParams(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));
  const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
  const jsonPublicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey);
  publicKeyProto.setX(
      Bytes.fromBase64(jsonPublicKey['x'], /* opt_webSafe = */ true));
  publicKeyProto.setY(
      Bytes.fromBase64(jsonPublicKey['y'], /* opt_webSafe = */ true));


  const privateKeyProto = new PbEciesAeadHkdfPrivateKey();
  privateKeyProto.setVersion(0);
  privateKeyProto.setPublicKey(publicKeyProto);
  const jsonPrivateKey =
      await EllipticCurves.exportCryptoKey(keyPair.privateKey);
  privateKeyProto.setKeyValue(
      Bytes.fromBase64(jsonPrivateKey['d'], /* opt_webSafe = */ true));

  return privateKeyProto;
};

/**
 * @param {PbEllipticCurveType=} opt_curveType (default: NIST_P256)
 * @param {PbHashType=} opt_hashType (default: SHA256)
 * @param {!PbKeyTemplate=} opt_keyTemplate (default: aes128CtrHmac256)
 * @param {PbPointFormat=} opt_pointFormat (default: UNCOMPRESSED)
 *
 * @return {!Promise<!PbEciesAeadHkdfPublicKey>}
 */
const createPublicKey = async function(
    opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat) {
  const key = await createPrivateKey(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat);
  return key.getPublicKey();
};
