/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {PbEciesAeadDemParams, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyTemplate, PbPointFormat} from '../internal/proto';
import * as Util from '../internal/util';
import * as Bytes from '../subtle/bytes';
import * as EllipticCurves from '../subtle/elliptic_curves';
import {assertExists} from '../testing/internal/test_utils';

import * as EciesAeadHkdfUtil from './ecies_aead_hkdf_util';

describe('ecies aead hkdf util test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('get json web key from proto, public key', async function() {
    for (const curve
             of [PbEllipticCurveType.NIST_P256,
                 PbEllipticCurveType.NIST_P384,
                 PbEllipticCurveType.NIST_P521,
    ]) {
      const key = await createKey(curve);
      const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(
          assertExists(key.getPublicKey()));

      // Test the returned jwk.
      const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
      const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);
      expect(jwk?.['kty']).toBe('EC');
      expect(jwk?.['crv']).toBe(curveTypeString);
      expect(Bytes.fromBase64(assertExists(jwk['x']), /* opt_webSafe = */ true))
          .toEqual(assertExists(key.getPublicKey()).getX_asU8());
      expect(Bytes.fromBase64(assertExists(jwk['y']), /* opt_webSafe = */ true))
          .toEqual(assertExists(key.getPublicKey()).getY_asU8());
      expect(jwk?.['d']).toEqual(undefined);
      expect(jwk?.['ext']).toBe(true);
    }
  });

  it('get json web key from proto, public key, with leading zeros',
     async function() {
       for (const curve
                of [PbEllipticCurveType.NIST_P256,
                    PbEllipticCurveType.NIST_P384,
                    PbEllipticCurveType.NIST_P521,
       ]) {
         const key = await createKey(curve);

         // Add leading zeros to x and y value of key.
         const x = assertExists(key.getPublicKey()).getX_asU8();
         const y = assertExists(key.getPublicKey()).getY_asU8();
         key.getPublicKey()?.setX(
             Bytes.concat(new Uint8Array([0, 0, 0, 0, 0]), x));
         key.getPublicKey()?.setY(Bytes.concat(new Uint8Array([0, 0, 0]), y));
         const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(
             assertExists(key.getPublicKey()));

         // Test the returned jwk.
         const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
         const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);
         expect(jwk?.['kty']).toBe('EC');
         expect(jwk?.['crv']).toBe(curveTypeString);
         expect(
             Bytes.fromBase64(assertExists(jwk['x']), /* opt_webSafe = */ true))
             .toEqual(x);
         expect(
             Bytes.fromBase64(assertExists(jwk['y']), /* opt_webSafe = */ true))
             .toEqual(y);
         expect(jwk?.['d']).toEqual(undefined);
         expect(jwk?.['ext']).toBe(true);
       }
     });

  it('get json web key from proto, public key, leading nonzero',
     async function() {
       const curve = PbEllipticCurveType.NIST_P256;
       const key = await createKey(curve);
       const publicKey = assertExists(key.getPublicKey());
       const x = publicKey.getX_asU8();
       publicKey.setX(Bytes.concat(new Uint8Array([1, 0]), x));
       try {
         EciesAeadHkdfUtil.getJsonWebKeyFromProto(publicKey);
         fail('An exception should be thrown.');
       } catch (e) {
         expect(e.toString())
             .toBe(
                 'SecurityException: Number needs more bytes to be represented.');
       }
     });

  it('get json web key from proto, private key', async function() {
    for (const curve
             of [PbEllipticCurveType.NIST_P256,
                 PbEllipticCurveType.NIST_P384,
                 PbEllipticCurveType.NIST_P521,
    ]) {
      const key = await createKey(curve);
      const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(key);

      // Test the returned jwk.
      const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
      const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);
      const publicKey = assertExists(key.getPublicKey());
      expect(jwk?.['kty']).toBe('EC');
      expect(jwk?.['crv']).toBe(curveTypeString);
      expect(Bytes.fromBase64(assertExists(jwk['x']), /* opt_webSafe = */ true))
          .toEqual(publicKey.getX_asU8());
      expect(Bytes.fromBase64(assertExists(jwk['y']), /* opt_webSafe = */ true))
          .toEqual(publicKey.getY_asU8());
      expect(Bytes.fromBase64(assertExists(jwk['d']), /* opt_webSafe = */ true))
          .toEqual(key.getKeyValue_asU8());
      expect(jwk?.['ext']).toBe(true);
    }
  });

  it('get json web key from proto, private key, leading zeros',
     async function() {
       for (const curve
                of [PbEllipticCurveType.NIST_P256,
                    PbEllipticCurveType.NIST_P384,
                    PbEllipticCurveType.NIST_P521,
       ]) {
         const key = await createKey(curve);
         const d = key.getKeyValue_asU8();
         key.setKeyValue(Bytes.concat(new Uint8Array([0, 0, 0]), d));
         const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(key);

         // Test the returned jwk.
         const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
         const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

         const publicKey = assertExists(key.getPublicKey());
         expect(jwk?.['kty']).toBe('EC');
         expect(jwk?.['crv']).toBe(curveTypeString);
         expect(
             Bytes.fromBase64(assertExists(jwk['x']), /* opt_webSafe = */ true))
             .toEqual(publicKey.getX_asU8());
         expect(
             Bytes.fromBase64(assertExists(jwk['y']), /* opt_webSafe = */ true))
             .toEqual(publicKey.getY_asU8());
         expect(
             Bytes.fromBase64(assertExists(jwk['d']), /* opt_webSafe = */ true))
             .toEqual(d);
         expect(jwk['ext']).toBe(true);
       }
     });
});

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

function createKeyParams(
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

async function createKey(
    opt_curveType: PbEllipticCurveType = PbEllipticCurveType.NIST_P256,
    opt_hashType?: PbHashType, opt_keyTemplate?: PbKeyTemplate,
    opt_pointFormat?: PbPointFormat): Promise<PbEciesAeadHkdfPrivateKey> {
  const curveTypeSubtle = Util.curveTypeProtoToSubtle((opt_curveType));
  const curveName = EllipticCurves.curveToString(curveTypeSubtle);

  const publicKeyProto =
      new PbEciesAeadHkdfPublicKey().setVersion(0).setParams(createKeyParams(
          opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));


  const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
  const publicKeyJson =
      await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
  publicKeyProto.setX(Bytes.fromBase64(
      assertExists(publicKeyJson['x']), /* opt_webSafe = */ true));
  publicKeyProto.setY(Bytes.fromBase64(
      assertExists(publicKeyJson['y']), /* opt_webSafe = */ true));

  const privateKeyProto = new PbEciesAeadHkdfPrivateKey();
  const privateKeyJson =
      await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
  privateKeyProto.setKeyValue(Bytes.fromBase64(
      assertExists(privateKeyJson['d']), /* opt_webSafe = */ true));
  privateKeyProto.setVersion(0);
  privateKeyProto.setPublicKey(publicKeyProto);

  return privateKeyProto;
}
