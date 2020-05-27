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

goog.module('tink.hybrid.EciesAeadHkdfUtilTest');
goog.setTestOnly('tink.hybrid.EciesAeadHkdfUtilTest');

const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const Bytes = goog.require('tink.subtle.Bytes');
const EciesAeadHkdfUtil = goog.require('tink.hybrid.EciesAeadHkdfUtil');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Util = goog.require('tink.Util');
const {PbEciesAeadDemParams, PbEciesAeadHkdfParams, PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey, PbEciesHkdfKemParams, PbEllipticCurveType, PbHashType, PbKeyTemplate, PbPointFormat} = goog.require('google3.third_party.tink.javascript.internal.proto');
const {assertExists} = goog.require('google3.third_party.tink.javascript.testing.internal.test_utils');

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
    const curves = Object.keys(PbEllipticCurveType);
    for (let curveId of curves) {
      const curve = PbEllipticCurveType[curveId];
      if (curve === PbEllipticCurveType.UNKNOWN_CURVE ||
          curve === PbEllipticCurveType.CURVE25519) {
        continue;
      }
      const key = await createKey(curve);
      const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(
          assertExists(key.getPublicKey()));

      // Test the returned jwk.
      const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
      const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

      expect(jwk['kty']).toBe('EC');
      expect(jwk['crv']).toBe(curveTypeString);
      expect(Bytes.fromBase64(jwk['x'], /* opt_webSafe = */ true))
          .toEqual(assertExists(key.getPublicKey()).getX_asU8());
      expect(Bytes.fromBase64(jwk['y'], /* opt_webSafe = */ true))
          .toEqual(assertExists(key.getPublicKey()).getY_asU8());
      expect(jwk['d']).toEqual(undefined);
      expect(jwk['ext']).toBe(true);
    }
  });

  it('get json web key from proto, public key, with leading zeros',
     async function() {
       const curves = Object.keys(PbEllipticCurveType);
       for (let curveId of curves) {
         const curve = PbEllipticCurveType[curveId];
         if (curve === PbEllipticCurveType.UNKNOWN_CURVE ||
             curve === PbEllipticCurveType.CURVE25519) {
           continue;
         }
         const key = await createKey(curve);
         // Add leading zeros to x and y value of key.
         const x = key.getPublicKey().getX_asU8();
         const y = key.getPublicKey().getY_asU8();
         key.getPublicKey().setX(
             Bytes.concat(new Uint8Array([0, 0, 0, 0, 0]), x));
         key.getPublicKey().setY(Bytes.concat(new Uint8Array([0, 0, 0]), y));
         const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(
             assertExists(key.getPublicKey()));

         // Test the returned jwk.
         const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
         const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

         expect(jwk['kty']).toBe('EC');
         expect(jwk['crv']).toBe(curveTypeString);
         expect(Bytes.fromBase64(jwk['x'], /* opt_webSafe = */ true))
             .toEqual(x);
         expect(Bytes.fromBase64(jwk['y'], /* opt_webSafe = */ true))
             .toEqual(y);
         expect(jwk['d']).toEqual(undefined);
         expect(jwk['ext']).toBe(true);
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
    const curves = Object.keys(PbEllipticCurveType);
    for (let curveId of curves) {
      const curve = PbEllipticCurveType[curveId];
      if (curve === PbEllipticCurveType.UNKNOWN_CURVE ||
          curve === PbEllipticCurveType.CURVE25519) {
        continue;
      }
      const key = await createKey(curve);
      const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(key);

      // Test the returned jwk.
      const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
      const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

      expect(jwk['kty']).toBe('EC');
      expect(jwk['crv']).toBe(curveTypeString);
      expect(Bytes.fromBase64(jwk['x'], /* opt_webSafe = */ true))
          .toEqual(key.getPublicKey().getX_asU8());
      expect(Bytes.fromBase64(jwk['y'], /* opt_webSafe = */ true))
          .toEqual(key.getPublicKey().getY_asU8());
      expect(Bytes.fromBase64(jwk['d'], /* opt_webSafe = */ true))
          .toEqual(key.getKeyValue_asU8());
      expect(jwk['ext']).toBe(true);
    }
  });

  it('get json web key from proto, private key, leading zeros',
     async function() {
       const curves = Object.keys(PbEllipticCurveType);
       for (let curveId of curves) {
         const curve = PbEllipticCurveType[curveId];
         if (curve === PbEllipticCurveType.UNKNOWN_CURVE ||
             curve === PbEllipticCurveType.CURVE25519) {
           continue;
         }
         const key = await createKey(curve);
         const d = key.getKeyValue_asU8();
         key.setKeyValue(Bytes.concat(new Uint8Array([0, 0, 0]), d));
         const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(key);

         // Test the returned jwk.
         const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
         const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

         expect(jwk['kty']).toBe('EC');
         expect(jwk['crv']).toBe(curveTypeString);
         expect(Bytes.fromBase64(jwk['x'], /* opt_webSafe = */ true))
             .toEqual(key.getPublicKey().getX_asU8());
         expect(Bytes.fromBase64(jwk['y'], /* opt_webSafe = */ true))
             .toEqual(key.getPublicKey().getY_asU8());
         expect(Bytes.fromBase64(jwk['d'], /* opt_webSafe = */ true))
             .toEqual(d);
         expect(jwk['ext']).toBe(true);
       }
     });
});

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
 * @return {!Promise<!PbEciesAeadHkdfPrivateKey>}
 */
const createKey = async function(
    opt_curveType = PbEllipticCurveType.NIST_P256, opt_hashType,
    opt_keyTemplate, opt_pointFormat) {
  const curveTypeSubtle = Util.curveTypeProtoToSubtle(
      /** @type {!PbEllipticCurveType} */ (opt_curveType));
  const curveName = EllipticCurves.curveToString(curveTypeSubtle);

  const publicKeyProto =
      new PbEciesAeadHkdfPublicKey().setVersion(0).setParams(createKeyParams(
          opt_curveType, opt_hashType, opt_keyTemplate, opt_pointFormat));


  const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
  const publicKeyJson = await EllipticCurves.exportCryptoKey(keyPair.publicKey);
  publicKeyProto.setX(
      Bytes.fromBase64(publicKeyJson['x'], /* opt_webSafe = */ true));
  publicKeyProto.setY(
      Bytes.fromBase64(publicKeyJson['y'], /* opt_webSafe = */ true));

  const privateKeyProto = new PbEciesAeadHkdfPrivateKey();
  const privateKeyJson =
      await EllipticCurves.exportCryptoKey(keyPair.privateKey);
  privateKeyProto.setKeyValue(
      Bytes.fromBase64(privateKeyJson['d'], /* opt_webSafe = */ true));
  privateKeyProto.setVersion(0);
  privateKeyProto.setPublicKey(publicKeyProto);

  return privateKeyProto;
};
