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

goog.module('tink.subtle.EllipticCurvesTest');
goog.setTestOnly('tink.subtle.EllipticCurvesTest');

const Bytes = goog.require('tink.subtle.Bytes');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Environment = goog.require('tink.subtle.Environment');
const Random = goog.require('tink.subtle.Random');
const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');
const wycheproofEcdhTestVectors = goog.require('tink.subtle.wycheproofEcdhTestVectors');

testSuite({
  shouldRunTests() {
    return Environment.IS_WEBCRYPTO_AVAILABLE &&
        !userAgent.EDGE;  // b/120286783
  },

  setUp() {
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  async testcomputeEcdhSharedSecret() {
    const aliceKeyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const bobKeyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const sharedSecret1 = await EllipticCurves.computeEcdhSharedSecret(
        aliceKeyPair.privateKey, bobKeyPair.publicKey);
    const sharedSecret2 = await EllipticCurves.computeEcdhSharedSecret(
        bobKeyPair.privateKey, aliceKeyPair.publicKey);
    assertEquals(Bytes.toHex(sharedSecret1), Bytes.toHex(sharedSecret2));
  },

  async testWycheproof_wycheproofWebcrypto() {
    for (let testGroup of wycheproofEcdhTestVectors['testGroups']) {
      let errors = '';
      for (let test of testGroup['tests']) {
        errors += await runWycheproofTest(test);
      }
      if (errors !== '') {
        fail(errors);
      }
    }
  },

  // Test that both ECDH public and private key are defined in the result.
  async testGenerateKeyPairECDH() {
    const curveTypes = Object.keys(EllipticCurves.CurveType);
    for (let curve of curveTypes) {
      const curveTypeString =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
      const keyPair =
          await EllipticCurves.generateKeyPair('ECDH', curveTypeString);
      assertTrue(keyPair.privateKey != null);
      assertTrue(keyPair.publicKey != null);
    }
  },

  // Test that both ECDSA public and private key are defined in the result.
  async testGenerateKeyPairECDSA() {
    const curveTypes = Object.keys(EllipticCurves.CurveType);
    for (let curve of curveTypes) {
      const curveTypeString =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
      const keyPair =
          await EllipticCurves.generateKeyPair('ECDSA', curveTypeString);
      assertTrue(keyPair.privateKey != null);
      assertTrue(keyPair.publicKey != null);
    }
  },

  // Test that when ECDH crypto key is exported and imported it gives the same
  // key as the original one.
  async testImportExportCryptoKeyECDH() {
    const curveTypes = Object.keys(EllipticCurves.CurveType);
    for (let curve of curveTypes) {
      const curveTypeString =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
      const keyPair =
          await EllipticCurves.generateKeyPair('ECDH', curveTypeString);

      const publicKey = keyPair.publicKey;
      const publicCryptoKey = await EllipticCurves.exportCryptoKey(publicKey);
      const importedPublicKey =
          await EllipticCurves.importPublicKey('ECDH', publicCryptoKey);
      assertObjectEquals(publicKey, importedPublicKey);

      const privateKey = keyPair.privateKey;
      const privateCryptoKey = await EllipticCurves.exportCryptoKey(privateKey);
      const importedPrivateKey =
          await EllipticCurves.importPrivateKey('ECDH', privateCryptoKey);
      assertObjectEquals(privateKey, importedPrivateKey);
    }
  },

  // Test that when ECDSA crypto key is exported and imported it gives the same
  // key as the original one.
  async testImportExportCryptoKeyECDSA() {
    const curveTypes = Object.keys(EllipticCurves.CurveType);
    for (let curve of curveTypes) {
      const curveTypeString =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
      const keyPair =
          await EllipticCurves.generateKeyPair('ECDSA', curveTypeString);

      const publicKey = keyPair.publicKey;
      const publicCryptoKey = await EllipticCurves.exportCryptoKey(publicKey);
      const importedPublicKey =
          await EllipticCurves.importPublicKey('ECDSA', publicCryptoKey);
      assertObjectEquals(publicKey, importedPublicKey);

      const privateKey = keyPair.privateKey;
      const privateCryptoKey = await EllipticCurves.exportCryptoKey(privateKey);
      const importedPrivateKey =
          await EllipticCurves.importPrivateKey('ECDSA', privateCryptoKey);
      assertObjectEquals(privateKey, importedPrivateKey);
    }
  },

  // Test that when JSON ECDH web key is imported and exported it gives the same
  // key as the original one.
  async testImportExportJsonKeyECDH() {
    for (let testKey of TEST_KEYS) {
      const jwk = /** @type{!webCrypto.JsonWebKey} */ ({
        'kty': 'EC',
        'crv': testKey.curve,
        'x': Bytes.toBase64(Bytes.fromHex(testKey.x), true),
        'y': Bytes.toBase64(Bytes.fromHex(testKey.y), true),
        'ext': true,
      });

      let importedKey;
      if (!testKey.d) {
        jwk['key_ops'] = [];
        importedKey = await EllipticCurves.importPublicKey('ECDH', jwk);
      } else {
        jwk['key_ops'] = ['deriveKey', 'deriveBits'];
        jwk['d'] = Bytes.toBase64(Bytes.fromHex(testKey.d), true);
        importedKey = await EllipticCurves.importPrivateKey('ECDH', jwk);
      }

      const exportedKey = await EllipticCurves.exportCryptoKey(importedKey);
      assertObjectEquals(jwk, exportedKey);
    }
  },

  // Test that when JSON ECDSA web key is imported and exported it gives the
  // same key as the original one.
  async testImportExportJsonKeyECDSA() {
    for (let testKey of TEST_KEYS) {
      const jwk = /** @type{!webCrypto.JsonWebKey} */ ({
        'kty': 'EC',
        'crv': testKey.curve,
        'x': Bytes.toBase64(Bytes.fromHex(testKey.x), true),
        'y': Bytes.toBase64(Bytes.fromHex(testKey.y), true),
        'ext': true,
      });

      let importedKey;
      if (!testKey.d) {
        jwk['key_ops'] = ['verify'];
        importedKey = await EllipticCurves.importPublicKey('ECDSA', jwk);
      } else {
        jwk['key_ops'] = ['sign'];
        jwk['d'] = Bytes.toBase64(Bytes.fromHex(testKey.d), true);
        importedKey = await EllipticCurves.importPrivateKey('ECDSA', jwk);
      }

      const exportedKey = await EllipticCurves.exportCryptoKey(importedKey);
      assertObjectEquals(jwk, exportedKey);
    }
  },

  testCurveToString() {
    assertEquals(
        'P-256', EllipticCurves.curveToString(EllipticCurves.CurveType.P256));
    assertEquals(
        'P-384', EllipticCurves.curveToString(EllipticCurves.CurveType.P384));
    assertEquals(
        'P-521', EllipticCurves.curveToString(EllipticCurves.CurveType.P521));
  },

  testCurveFromString() {
    assertEquals(
        EllipticCurves.CurveType.P256, EllipticCurves.curveFromString('P-256'));
    assertEquals(
        EllipticCurves.CurveType.P384, EllipticCurves.curveFromString('P-384'));
    assertEquals(
        EllipticCurves.CurveType.P521, EllipticCurves.curveFromString('P-521'));
  },

  testFieldSizeInBytes() {
    assertEquals(
        256 / 8,
        EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P256));
    assertEquals(
        384 / 8,
        EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P384));
    assertEquals(
        (521 + 7) / 8,
        EllipticCurves.fieldSizeInBytes(EllipticCurves.CurveType.P521));
  },

  testEncodingSizeInBytes_uncompressedPointFormatType() {
    assertEquals(
        2 * (256 / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P256,
            EllipticCurves.PointFormatType.UNCOMPRESSED));
    assertEquals(
        2 * (384 / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P384,
            EllipticCurves.PointFormatType.UNCOMPRESSED));
    assertEquals(
        2 * ((521 + 7) / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P521,
            EllipticCurves.PointFormatType.UNCOMPRESSED));
  },

  testEncodingSizeInBytes_compressedPointFormatType() {
    assertEquals(
        (256 / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P256,
            EllipticCurves.PointFormatType.COMPRESSED));
    assertEquals(
        (384 / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P384,
            EllipticCurves.PointFormatType.COMPRESSED));
    assertEquals(
        ((521 + 7) / 8) + 1,
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P521,
            EllipticCurves.PointFormatType.COMPRESSED));
  },

  testEncodingSizeInBytes_crunchyUncompressedPointFormatType() {
    assertEquals(
        2 * (256 / 8),
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P256,
            EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
    assertEquals(
        2 * (384 / 8),
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P384,
            EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
    assertEquals(
        2 * ((521 + 7) / 8),
        EllipticCurves.encodingSizeInBytes(
            EllipticCurves.CurveType.P521,
            EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
  },

  testPointDecode_wrongPointSize() {
    const point = new Uint8Array(10);
    const format = EllipticCurves.PointFormatType.UNCOMPRESSED;

    for (let curve of Object.keys(EllipticCurves.CurveType)) {
      const curveTypeString =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);

      // It should throw an exception as the point array is too short.
      try {
        EllipticCurves.pointDecode(curveTypeString, format, point);
        fail('Should throw an exception.');
      } catch (e) {
        assertEquals('CustomError: invalid point', e.toString());
      }
    }
  },

  testPointDecode_unknownCurve() {
    const point = new Uint8Array(10);
    const format = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const curve = 'some-unknown-curve';

    try {
      EllipticCurves.pointDecode(curve, format, point);
      fail('Should throw an exception.');
    } catch (e) {
      assertTrue(e.toString().includes('unknown curve'));
    }
  },

  testPointEncodeDecode() {
    const format = EllipticCurves.PointFormatType.UNCOMPRESSED;
    for (let curve of Object.keys(EllipticCurves.CurveType)) {
      const curveType = EllipticCurves.CurveType[curve];
      const curveTypeString = EllipticCurves.curveToString(curveType);
      const x = Random.randBytes(EllipticCurves.fieldSizeInBytes(curveType));
      const y = Random.randBytes(EllipticCurves.fieldSizeInBytes(curveType));

      const point = /** @type {!webCrypto.JsonWebKey} */ ({
        'kty': 'EC',
        'crv': curveTypeString,
        'x': Bytes.toBase64(x, /* websafe = */ true),
        'y': Bytes.toBase64(y, /* websafe = */ true),
        'ext': true,
      });

      const encodedPoint =
          EllipticCurves.pointEncode(point['crv'], format, point);
      const decodedPoint =
          EllipticCurves.pointDecode(curveTypeString, format, encodedPoint);

      assertObjectEquals(point, decodedPoint);
    }
  },

  testEcdsaDer2Ieee() {
    for (let test of ECDSA_IEEE_DER_TEST_VECTORS) {
      assertObjectEquals(
          test.ieee, EllipticCurves.ecdsaDer2Ieee(test.der, test.ieee.length));
    }
  },

  testEcdsaDer2IeeeWithInvalidSignatures() {
    for (let test of INVALID_DER_ECDSA_SIGNATURES) {
      try {
        EllipticCurves.ecdsaDer2Ieee(
            Bytes.fromHex(test), 1 /* ieeeLength, ignored */);
      } catch (e) {
        assertEquals('CustomError: invalid DER signature', e.toString());
      }
    }
  },

  testEcdsaIeee2Der() {
    for (let test of ECDSA_IEEE_DER_TEST_VECTORS) {
      assertObjectEquals(test.der, EllipticCurves.ecdsaIeee2Der(test.ieee));
    }
  },

  testIsValidDerEcdsaSignature() {
    for (let test of INVALID_DER_ECDSA_SIGNATURES) {
      assertFalse(EllipticCurves.isValidDerEcdsaSignature(Bytes.fromHex(test)));
    }
  },
});

/**
 * Runs the test with test vector given as an input and returns either empty
 * string or a text describing the failure.
 *
 * @param {!Object} test - JSON object with test data
 * @return {!Promise<string>}
 */
const runWycheproofTest = async function(test) {
  try {
    const privateKey =
        await EllipticCurves.importPrivateKey('ECDH', test['private']);
    try {
      const publicKey =
          await EllipticCurves.importPublicKey('ECDH', test['public']);
      const sharedSecret =
          await EllipticCurves.computeEcdhSharedSecret(privateKey, publicKey);
      if (test['result'] === 'invalid') {
        return 'Fail on test ' + test['tcId'] + ': No exception thrown.\n';
      }
      const sharedSecretHex = Bytes.toHex(sharedSecret);
      if (sharedSecretHex !== test['shared']) {
        return 'Fail on test ' + test['tcId'] + ': unexpected result was \"' +
            sharedSecretHex + '\".\n';
      }
    } catch (e) {
      if (test['result'] === 'valid') {
        return 'Fail on test ' + test['tcId'] + ': unexpected exception \"' +
            e.toString() + '\".\n';
      }
    }
  } catch (e) {
    if (test['result'] === 'valid') {
      if (test['private']['crv'] == "P-256K") {
        // P-256K doesn't have to be supported. Hence failing to import the
        // key is OK.
        return '';
      }
      return 'Fail on test ' + test['tcId'] +
          ': unexpected exception trying to import private key \"' +
          e.toString() + '\".\n';
    }
  }
  // If the test passes return an empty string.
  return '';
};

class TestKey {
  /**
   * @param {string} curve
   * @param {string} x
   * @param {string} y
   * @param {string=} opt_d
   */
  constructor(curve, x, y, opt_d) {
    /** @const {string} */
    this.curve = curve;
    /** @const {string} */
    this.x = x;
    /** @const {string} */
    this.y = y;
    /** @const {string|undefined} */
    this.d = opt_d;
  }
}

// This set of keys was generated by Java version of Tink.
// It contains one private and one public key for each curve type supported by
// Tink.
/** @type {!Array<!TestKey>} */
const TEST_KEYS = [
  new TestKey(
      /* curve = */ 'P-256',
      /* x = */
      '2eab800e5d8e9b15d0f87c55324b477ffc9382d7137599e0203113a4e41b50d0',
      /* y = */
      '50bb2c11cfb72f3c380c2f93ea088d6938b91bcf581cd94a73ed0a3f623a6b8b'),
  new TestKey(
      /* curve = */ 'P-256',
      /* x = */
      '844c085cc4450297b681126356e10da074dea817f69bc2b1f3d6b1fc82593c7d',
      /* y = */
      '3cdb41fc89867d2066cc9c4f9ad7e890152bad24de20621abfe608234cbe40f1',
      /* opt_d = */
      'f96796cc28b36038817cc5d7db01c52ee0411dd848dc0833e9e26e989e4a64db'),
  new TestKey(
      /* curve = */ 'P-384',
      /* x = */
      'f3290cc80faa65e8821b0bf835f51e3431a4d78dcebd81b74c53b9b704bd995df93b648d51057a9a96a654fb8332391e',
      /* y = */
      '7e52bb9f654781a6894ef5ae77869207fa32ddbcec4a02d27ba1ead5472b3b9f39b09e9bca7d936809c143e99c655401'),
  new TestKey(
      /* curve = */ 'P-384',
      /* x = */
      'be9df79abedb82fc0e527630955f63f2f74b4984f0a4ac063a089565393ed20ac7a784f4efa434f5b1fa1837c76c8472',
      /* y = */
      'cf34ad0d4f3f2cbd546780509ec7073bb26fa0547d09ed10b83bf9b90903037ac956dbd661d02ce3e397e0547356b331',
      /* opt_d = */
      '34d86595280a8bdca23ccd60eeac9581016e895c2bc867c26dc2f99f6d0f627ce586ad36d1d2981968d8852dc9276d12'),
  new TestKey(
      /* curve = */ 'P-521',
      /* x = */
      '012f2211ec7e634919857be3066becf20c438b84ff24501712c91c98f527b44c7b001f8611935cb1179541c2b3cc3a1fc9259d50cd4842a847ea0cafe22cd75fe788',
      /* y = */
      '016b5d3f5480122643a26ef9e7c7e36875f53c28167d6afc35777d32ea76127d34287325bf14779f2e4cf3864fcc951ba601cec92b03291e34db2e815d4bd6fc2045'),
  new TestKey(
      /* curve = */ 'P-521',
      /* x = */
      '01ee3aabecef323cb4581e044be21914b567c426eae18d71720a71a0b236f5324ef9666fe855f5d7986d3e33a9250396f63c780572b3ad9417d69c2a87773ce39194',
      /* y = */
      '0036bea90db019304719d269e5335f9790e730e241a1b02cfdab8bdcfd0bcff8bdcb3ddeb9c3a94ecff1ab6abb80b0c1655f871c6089d3a4bf8625cf6bd182897f1b',
      /* opt_d = */
      '00b9f9f5d91cbfa9b7f92b041b137ac9822ca4a38f71ce227f624cac6178ca8351fab24bc2cc3f85d7ab72f54a0f9d1bb11a888a79a9c7b1ca267ddc82043585e437')
];

class EcdsaIeeeDerTestVector {
  /**
   * @param {string} ieee
   * @param {string} der
   */
  constructor(ieee, der) {
    /** @const {!Uint8Array} */
    this.ieee = Bytes.fromHex(ieee);
    /** @const {!Uint8Array} */
    this.der = Bytes.fromHex(der);
  }
}

/** @type {!Array<!EcdsaIeeeDerTestVector>} */
const ECDSA_IEEE_DER_TEST_VECTORS = [
  new EcdsaIeeeDerTestVector(  // normal case, short-form length
      '0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10',
      '302402100102030405060708090a0b0c0d0e0f1002100102030405060708090a0b0c0d0e0f10'),
  new EcdsaIeeeDerTestVector(  // normal case, long-form length
      '010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203',
      '30818802420100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000002030242010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000100000001000000010000000203'),
  new EcdsaIeeeDerTestVector(  // zero prefix.
      '0002030405060708090a0b0c0d0e0f100002030405060708090a0b0c0d0e0f10',
      '3022020f02030405060708090a0b0c0d0e0f10020f02030405060708090a0b0c0d0e0f10'),
  new EcdsaIeeeDerTestVector(  // highest bit is set.
      '00ff030405060708090a0b0c0d0e0f1000ff030405060708090a0b0c0d0e0f10',
      '3024021000ff030405060708090a0b0c0d0e0f10021000ff030405060708090a0b0c0d0e0f10'),
  new EcdsaIeeeDerTestVector(  // highest bit is set, full length.
      'ff02030405060708090a0b0c0d0e0f10ff02030405060708090a0b0c0d0e0f10',
      '3026021100ff02030405060708090a0b0c0d0e0f10021100ff02030405060708090a0b0c0d0e0f10'),
  new EcdsaIeeeDerTestVector(  // all zeros.
      '0000000000000000000000000000000000000000000000000000000000000000',
      '3006020100020100'),
];

/** @type {!Array<string>} */
const INVALID_DER_ECDSA_SIGNATURES = [
  '2006020101020101',    // 1st byte is not 0x30 (SEQUENCE tag)
  '3006050101020101',    // 3rd byte is not 0x02 (INTEGER tag)
  '3006020101050101',    // 6th byte is not 0x02 (INTEGER tag)
  '308206020101020101',  // long form length is not 0x81
  '30ff020101020101',    // invalid total length
  '3006020201020101',    // invalid rLength
  '3006020101020201',    // invalid sLength
  '30060201ff020101',    // no extra zero when highest bit of r is set
  '30060201010201ff',    // no extra zero when highest bit of s is set
];
