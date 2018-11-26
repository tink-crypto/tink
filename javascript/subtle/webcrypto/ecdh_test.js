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

goog.module('tink.subtle.webcrypto.EcdhTest');
goog.setTestOnly('tink.subtle.webcrypto.EcdhTest');

const Bytes = goog.require('tink.subtle.Bytes');
const Ecdh = goog.require('tink.subtle.webcrypto.Ecdh');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');
const wycheproofTestVectors = goog.require('tink.subtle.webcrypto.wycheproofTestVectors');


testSuite({
  setUp() {
    // Use a generous promise timeout for running continuously.
    TestCase.getActiveTestCase().promiseTimeout = 1000 * 1000;  // 1000s
  },

  tearDown() {
    // Reset the promise timeout to default value.
    TestCase.getActiveTestCase().promiseTimeout = 1000;  // 1s
  },

  async testComputeSharedSecret() {
    const aliceKeyPair = await Ecdh.generateKeyPair('P-256');
    const bobKeyPair = await Ecdh.generateKeyPair('P-256');
    const sharedSecret1 = await Ecdh.computeSharedSecret(
        aliceKeyPair.privateKey, bobKeyPair.publicKey);
    const sharedSecret2 = await Ecdh.computeSharedSecret(
        bobKeyPair.privateKey, aliceKeyPair.publicKey);
    assertEquals(Bytes.toHex(sharedSecret1), Bytes.toHex(sharedSecret2));
  },

  async testWycheproof_wycheproofWebcrypto() {
    for (let testGroup of wycheproofTestVectors['testGroups']) {
      let errors = '';
      for (let test of testGroup['tests']) {
        errors += await runWycheproofTest(test);
      }
      if (errors !== '') {
        fail(errors);
      }
    }
  },

  // Test that both public and private key are defined in the result.
  async testGenerateKeyPair() {
    const curveTypes = Object.keys(EllipticCurves.CurveType);
    for (let curve of curveTypes) {
      const curveTypeString =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
      const keyPair = await Ecdh.generateKeyPair(curveTypeString);
      assertTrue(keyPair.privateKey != null);
      assertTrue(keyPair.publicKey != null);
    }
  },

  // Test that when crypto key is exported and imported it gives the same key
  // as the original one.
  async testExportImportCryptoKey() {
    const curveTypes = Object.keys(EllipticCurves.CurveType);
    for (let curve of curveTypes) {
      const curveTypeString =
          EllipticCurves.curveToString(EllipticCurves.CurveType[curve]);
      const keyPair = await Ecdh.generateKeyPair(curveTypeString);

      const publicKey = keyPair.publicKey;
      const publicCryptoKey = await Ecdh.exportCryptoKey(publicKey);
      const importedPublicKey = await Ecdh.importPublicKey(publicCryptoKey);
      assertObjectEquals(publicKey, importedPublicKey);

      const privateKey = keyPair.privateKey;
      const privateCryptoKey = await Ecdh.exportCryptoKey(privateKey);
      const importedPrivateKey = await Ecdh.importPrivateKey(privateCryptoKey);
      assertObjectEquals(privateKey, importedPrivateKey);
    }
  },

  // Test that when JSON web key is imported and exported it gives the same key
  // as the original one.
  async testImportExportJsonKey() {
    for (let testKey of TEST_KEYS) {
      const jwk = /** @type{webCrypto.JsonWebKey} */ ({
        'kty': 'EC',
        'crv': testKey.curve,
        'x': Bytes.toBase64(Bytes.fromHex(testKey.x), true),
        'y': Bytes.toBase64(Bytes.fromHex(testKey.y), true),
        'ext': true,
      });

      let importedKey;
      if (!testKey.d) {
        jwk['key_ops'] = [];
        importedKey = await Ecdh.importPublicKey(jwk);
      } else {
        jwk['key_ops'] = ['deriveKey', 'deriveBits'];
        jwk['d'] = Bytes.toBase64(Bytes.fromHex(testKey.d), true);
        importedKey = await Ecdh.importPrivateKey(jwk);
      }

      const exportedKey = await Ecdh.exportCryptoKey(importedKey);
      assertObjectEquals(jwk, exportedKey);
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
    const publicKey = await Ecdh.importPublicKey(test['public']);
    const privateKey = await Ecdh.importPrivateKey(test['private']);
    const sharedSecret = await Ecdh.computeSharedSecret(privateKey, publicKey);
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
/** {!Array<!TestKey>} */
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
