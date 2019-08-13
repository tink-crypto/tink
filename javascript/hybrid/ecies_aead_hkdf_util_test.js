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
const PbEciesAeadDemParams = goog.require('proto.google.crypto.tink.EciesAeadDemParams');
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

  async testGetJsonWebKeyFromProto_publicKey() {
    const curves = Object.keys(PbEllipticCurveType);
    for (let curveId of curves) {
      const curve = PbEllipticCurveType[curveId];
      if (curve === PbEllipticCurveType.UNKNOWN_CURVE) {
        continue;
      }
      const key = await createKey(curve);
      const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(key.getPublicKey());

      // Test the returned jwk.
      const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
      const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

      assertEquals('EC', jwk['kty']);
      assertEquals(curveTypeString, jwk['crv']);
      assertObjectEquals(
          key.getPublicKey().getX_asU8(),
          Bytes.fromBase64(jwk['x'], /* opt_webSafe = */ true));
      assertObjectEquals(
          key.getPublicKey().getY_asU8(),
          Bytes.fromBase64(jwk['y'], /* opt_webSafe = */ true));
      assertObjectEquals(undefined, jwk['d']);
      assertTrue(jwk['ext']);
    }
  },

  async testGetJsonWebKeyFromProto_publicKey_withLeadingZeros() {
    const curves = Object.keys(PbEllipticCurveType);
    for (let curveId of curves) {
      const curve = PbEllipticCurveType[curveId];
      if (curve === PbEllipticCurveType.UNKNOWN_CURVE) {
        continue;
      }
      const key = await createKey(curve);
      // Add leading zeros to x and y value of key.
      const x = key.getPublicKey().getX();
      const y = key.getPublicKey().getY();
      key.getPublicKey().setX(Bytes.concat(new Uint8Array([0, 0, 0, 0, 0]), x));
      key.getPublicKey().setY(Bytes.concat(new Uint8Array([0, 0, 0]), y));
      const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(key.getPublicKey());

      // Test the returned jwk.
      const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
      const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

      assertEquals('EC', jwk['kty']);
      assertEquals(curveTypeString, jwk['crv']);
      assertObjectEquals(
          x, Bytes.fromBase64(jwk['x'], /* opt_webSafe = */ true));
      assertObjectEquals(
          y, Bytes.fromBase64(jwk['y'], /* opt_webSafe = */ true));
      assertObjectEquals(undefined, jwk['d']);
      assertTrue(jwk['ext']);
    }
  },

  async testGetJsonWebKeyFromProto_publicKey_leadingNonzero() {
    const curve = PbEllipticCurveType.NIST_P256;
    const key = await createKey(curve);
    const x = key.getPublicKey().getX();
    key.getPublicKey().setX(Bytes.concat(new Uint8Array([1, 0]), x));
    try {
      EciesAeadHkdfUtil.getJsonWebKeyFromProto(key.getPublicKey());
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          'CustomError: Number needs more bytes to be represented.',
          e.toString());
    }
  },

  async testGetJsonWebKeyFromProto_privateKey() {
    const curves = Object.keys(PbEllipticCurveType);
    for (let curveId of curves) {
      const curve = PbEllipticCurveType[curveId];
      if (curve === PbEllipticCurveType.UNKNOWN_CURVE) {
        continue;
      }
      const key = await createKey(curve);
      const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(key);

      // Test the returned jwk.
      const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
      const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

      assertEquals('EC', jwk['kty']);
      assertEquals(curveTypeString, jwk['crv']);
      assertObjectEquals(
          key.getPublicKey().getX_asU8(),
          Bytes.fromBase64(jwk['x'], /* opt_webSafe = */ true));
      assertObjectEquals(
          key.getPublicKey().getY_asU8(),
          Bytes.fromBase64(jwk['y'], /* opt_webSafe = */ true));
      assertObjectEquals(
          key.getKeyValue_asU8(),
          Bytes.fromBase64(jwk['d'], /* opt_webSafe = */ true));
      assertTrue(jwk['ext']);
    }
  },

  async testGetJsonWebKeyFromProto_privateKey_leadingZeros() {
    const curves = Object.keys(PbEllipticCurveType);
    for (let curveId of curves) {
      const curve = PbEllipticCurveType[curveId];
      if (curve === PbEllipticCurveType.UNKNOWN_CURVE) {
        continue;
      }
      const key = await createKey(curve);
      const d = key.getKeyValue_asU8();
      key.setKeyValue(Bytes.concat(new Uint8Array([0, 0, 0]), d));
      const jwk = EciesAeadHkdfUtil.getJsonWebKeyFromProto(key);

      // Test the returned jwk.
      const curveTypeSubtle = Util.curveTypeProtoToSubtle(curve);
      const curveTypeString = EllipticCurves.curveToString(curveTypeSubtle);

      assertEquals('EC', jwk['kty']);
      assertEquals(curveTypeString, jwk['crv']);
      assertObjectEquals(
          key.getPublicKey().getX_asU8(),
          Bytes.fromBase64(jwk['x'], /* opt_webSafe = */ true));
      assertObjectEquals(
          key.getPublicKey().getY_asU8(),
          Bytes.fromBase64(jwk['y'], /* opt_webSafe = */ true));
      assertObjectEquals(
          d, Bytes.fromBase64(jwk['d'], /* opt_webSafe = */ true));
      assertTrue(jwk['ext']);
    }
  },
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
