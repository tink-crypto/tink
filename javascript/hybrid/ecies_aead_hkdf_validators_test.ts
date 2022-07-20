/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {PbEciesAeadDemParams, PbEciesAeadHkdfKeyFormat, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyTemplate, PbPointFormat} from '../internal/proto';
import * as Util from '../internal/util';
import * as Bytes from '../subtle/bytes';
import * as EllipticCurves from '../subtle/elliptic_curves';
import {assertExists} from '../testing/internal/test_utils';

import * as EciesAeadHkdfValidators from './ecies_aead_hkdf_validators';


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
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingKemParams());
    }
  });

  it('validate params, invalid kem params, unknown hash type', function() {
    const invalidParams = createParams();
    invalidParams.getKemParams()?.setHkdfHashType(PbHashType.UNKNOWN_HASH);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownHashType());
    }
  });

  it('validate params, invalid kem params, unknown curve type', function() {
    const invalidParams = createParams();
    invalidParams.getKemParams()?.setCurveType(
        PbEllipticCurveType.UNKNOWN_CURVE);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownCurveType());
    }
  });

  it('validate params, missing dem params', function() {
    const invalidParams = createParams().setDemParams(null);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingDemParams());
    }
  });

  it('validate params, invalid dem params, missing aead template', function() {
    const invalidParams = createParams();
    invalidParams.getDemParams()?.setAeadDem(null);

    try {
      EciesAeadHkdfValidators.validateParams(invalidParams);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingAeadTemplate());
    }
  });

  it('validate params, invalid dem params, unsupported aead template',
     function() {
       const unsupportedTypeUrl = 'UNSUPPORTED_KEY_TYPE_URL';
       const invalidParams = createParams();
       invalidParams.getDemParams()?.getAeadDem()?.setTypeUrl(
           unsupportedTypeUrl);

       try {
         EciesAeadHkdfValidators.validateParams(invalidParams);
         fail('An exception should be thrown.');
       } catch (e: any) {
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
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownPointFormat());
    }
  });
  it('validate params, different valid values', function() {
    for (const curve
             of [PbEllipticCurveType.NIST_P256,
                 PbEllipticCurveType.NIST_P384,
                 PbEllipticCurveType.NIST_P521,
    ]) {
      for (const hashType
               of [PbHashType.SHA1,
                   PbHashType.SHA384,
                   PbHashType.SHA256,
                   PbHashType.SHA512,
      ]) {
        for (const keyTemplate
                 of [AeadKeyTemplates.aes128CtrHmacSha256(),
                     AeadKeyTemplates.aes128Gcm(),
        ]) {
          for (const pointFormat
                   of [PbPointFormat.UNCOMPRESSED,
                       PbPointFormat.COMPRESSED,
                       PbPointFormat.DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
          ]) {
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
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingFormatParams());
    }
  });

  it('validate key format, invalid params', function() {
    const invalidKeyFormat =
        new PbEciesAeadHkdfKeyFormat().setParams(createParams());

    // Check that also params were checked.
    // Test missing DEM params.
    invalidKeyFormat.getParams()?.setDemParams(null);
    try {
      EciesAeadHkdfValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingDemParams());
    }
    invalidKeyFormat.getParams()?.setDemParams(createDemParams());

    // Test UNKNOWN_HASH in KEM params.
    invalidKeyFormat.getParams()?.getKemParams()?.setHkdfHashType(
        PbHashType.UNKNOWN_HASH);
    try {
      EciesAeadHkdfValidators.validateKeyFormat(invalidKeyFormat);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.unknownHashType());
    }
  });

  it('validate public key, missing params', function() {
    const invalidPublicKey = new PbEciesAeadHkdfPublicKey();

    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e: any) {
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
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingXY());
    }

    // The key with only Y set to empty is also invalid.
    invalidPublicKey.setX(new Uint8Array(10));
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingXY());
    }

    // The key with only X set to empty is also invalid.
    invalidPublicKey.setY(new Uint8Array(10));
    invalidPublicKey.setX(new Uint8Array(0));
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingXY());
    }
  });

  it('validate public key, invalid params', async function() {
    const invalidPublicKey = await createPublicKey();

    // Check that also params were checked.
    // Test missing DEM params.
    invalidPublicKey.getParams()?.setDemParams(null);
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingDemParams());
    }
    invalidPublicKey.getParams()?.setDemParams(createDemParams());

    // Test UNKNOWN_HASH in KEM params.
    invalidPublicKey.getParams()?.getKemParams()?.setHkdfHashType(
        PbHashType.UNKNOWN_HASH);
    try {
      EciesAeadHkdfValidators.validatePublicKey(invalidPublicKey, 0);
      fail('An exception should be thrown.');
    } catch (e: any) {
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
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.versionOutOfBounds(managerVersion));
    }
  });

  it('validate private key, missing public key', async function() {
    const invalidPrivateKey = (await createPrivateKey()).setPublicKey(null);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(invalidPrivateKey, 0, 0);
      fail('An exception should be thrown.');
    } catch (e: any) {
      expect(e.toString()).toBe(ExceptionText.missingPublicKey());
    }
  });

  it('validate private key, invalid public key', async function() {
    const invalidPrivateKey = await createPrivateKey();
    invalidPrivateKey.getPublicKey()?.setParams(null);
    try {
      EciesAeadHkdfValidators.validatePrivateKey(invalidPrivateKey, 0, 0);
      fail('An exception should be thrown.');
    } catch (e: any) {
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
    } catch (e: any) {
      expect(e.toString())
          .toBe(ExceptionText.versionOutOfBounds(managerVersion));
    }
  });
});

// Helper classes and functions
class ExceptionText {
  static missingFormatParams(): string {
    return 'SecurityException: Invalid key format - missing key params.';
  }

  static missingKeyParams(): string {
    return 'SecurityException: Invalid public key - missing key params.';
  }

  static unknownPointFormat(): string {
    return 'SecurityException: Invalid key params - unknown EC point format.';
  }

  static missingKemParams(): string {
    return 'SecurityException: Invalid params - missing KEM params.';
  }

  static unknownHashType(): string {
    return 'SecurityException: Invalid KEM params - unknown hash type.';
  }

  static unknownCurveType(): string {
    return 'SecurityException: Invalid KEM params - unknown curve type.';
  }

  static missingDemParams(): string {
    return 'SecurityException: Invalid params - missing DEM params.';
  }

  static missingAeadTemplate(): string {
    return 'SecurityException: Invalid DEM params - missing AEAD key template.';
  }

  static unsupportedKeyTemplate(templateTypeUrl: string): string {
    return 'SecurityException: Invalid DEM params - ' + templateTypeUrl +
        ' template is not supported by ECIES AEAD HKDF.';
  }

  static missingXY(): string {
    return 'SecurityException: Invalid public key - missing value of X or Y.';
  }

  static missingPublicKey(): string {
    return 'SecurityException: Invalid private key - missing public key information.';
  }

  static missingPrivateKeyValue(): string {
    return 'SecurityException: Invalid private key - missing private key value.';
  }

  static versionOutOfBounds(version: number): string {
    return 'SecurityException: Version is out of bound, must be between 0 and ' +
        version + '.';
  }
}

function createKemParams(
    opt_curveType: PbEllipticCurveType = PbEllipticCurveType.NIST_P256,
    opt_hashType: PbHashType = PbHashType.SHA256): PbEciesHkdfKemParams {
  const kemParams = new PbEciesHkdfKemParams()
                        .setCurveType(opt_curveType)
                        .setHkdfHashType(opt_hashType);

  return kemParams;
}

function createDemParams(opt_keyTemplate?: PbKeyTemplate):
    PbEciesAeadDemParams {
  if (!opt_keyTemplate) {
    opt_keyTemplate = AeadKeyTemplates.aes128CtrHmacSha256();
  }

  const demParams = new PbEciesAeadDemParams().setAeadDem(opt_keyTemplate);

  return demParams;
}

function createParams(
    opt_curveType?: PbEllipticCurveType, opt_hashType?: PbHashType,
    opt_keyTemplate?: PbKeyTemplate,
    opt_pointFormat: PbPointFormat =
        PbPointFormat.UNCOMPRESSED): PbEciesAeadHkdfParams {
  const params = new PbEciesAeadHkdfParams()
                     .setKemParams(createKemParams(opt_curveType, opt_hashType))
                     .setDemParams(createDemParams(opt_keyTemplate))
                     .setEcPointFormat(opt_pointFormat);

  return params;
}

async function createPrivateKey(
    opt_curveType: PbEllipticCurveType = PbEllipticCurveType.NIST_P256,
    opt_hashType?: PbHashType, opt_keyTemplate?: PbKeyTemplate,
    opt_pointFormat?: PbPointFormat): Promise<PbEciesAeadHkdfPrivateKey> {
  const curveSubtleType = Util.curveTypeProtoToSubtle(opt_curveType);
  const curveName = EllipticCurves.curveToString(curveSubtleType);

  const publicKeyProto =
      new PbEciesAeadHkdfPublicKey().setVersion(0).setParams(createParams(
          opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));
  const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
  const jsonPublicKey =
      await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
  publicKeyProto.setX(Bytes.fromBase64(
      assertExists(jsonPublicKey['x']), /* opt_webSafe = */ true));
  publicKeyProto.setY(Bytes.fromBase64(
      assertExists(jsonPublicKey['y']), /* opt_webSafe = */ true));


  const privateKeyProto =
      new PbEciesAeadHkdfPrivateKey().setVersion(0).setPublicKey(
          publicKeyProto);
  const jsonPrivateKey =
      await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
  privateKeyProto.setKeyValue(Bytes.fromBase64(
      assertExists(jsonPrivateKey['d']), /* opt_webSafe = */ true));

  return privateKeyProto;
}

async function createPublicKey(
    opt_curveType?: PbEllipticCurveType, opt_hashType?: PbHashType,
    opt_keyTemplate?: PbKeyTemplate,
    opt_pointFormat?: PbPointFormat): Promise<PbEciesAeadHkdfPublicKey> {
  const key = await createPrivateKey(
      opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat);
  return assertExists(key.getPublicKey());
}
