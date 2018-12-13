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

goog.module('tink.subtle.EcdsaVerifyTest');
goog.setTestOnly('tink.subtle.EcdsaVerifyTest');

const Bytes = goog.require('tink.subtle.Bytes');
const EcdsaSign = goog.require('tink.subtle.EcdsaSign');
const EcdsaVerify = goog.require('tink.subtle.EcdsaVerify');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Environment = goog.require('tink.subtle.Environment');
const Random = goog.require('tink.subtle.Random');
const TestCase = goog.require('goog.testing.TestCase');
const Validators = goog.require('tink.subtle.Validators');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');
const wycheproofEcdsaTestVectors = goog.require('tink.subtle.wycheproofEcdsaTestVectors');

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

  async testVerify() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await EcdsaSign.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
    const verifier = await EcdsaVerify.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
    for (let i = 0; i < 100; i++) {
      const data = Random.randBytes(i);
      const signature = await signer.sign(data);
      assertTrue(await verifier.verify(signature, data));
    }
  },

  async testVerifyWithDerEncoding() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await EcdsaSign.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256',
        EllipticCurves.EcdsaSignatureEncodingType.DER);
    const verifier = await EcdsaVerify.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
    const verifierDer = await EcdsaVerify.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256',
        EllipticCurves.EcdsaSignatureEncodingType.DER);
    for (let i = 0; i < 100; i++) {
      const data = Random.randBytes(i);
      const signature = await signer.sign(data);
      assertFalse(await verifier.verify(signature, data));
      assertTrue(await verifierDer.verify(signature, data));
    }
  },

  async testConstructorWithNullPublicKey() {
    try {
      await EcdsaVerify.newInstance(null, 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: public key has to be non-null', e.toString());
    }
  },

  async testConstructorWithInvalidHash() {
    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
      await EcdsaVerify.newInstance(
          await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-1');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-256 (because curve is P-256) but got SHA-1',
          e.toString());
    }

    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-384');
      await EcdsaVerify.newInstance(
          await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256',
          e.toString());
    }

    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-521');
      await EcdsaVerify.newInstance(
          await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-512 (because curve is P-521) but got SHA-256',
          e.toString());
    }
  },

  async testConstructorWithInvalidCurve() {
    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
      const jwk = await EllipticCurves.exportCryptoKey(keyPair.publicKey);
      jwk.crv = 'blah';
      await EcdsaVerify.newInstance(jwk, 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: unsupported curve: blah', e.toString());
    }
  },

  async testVerifyModifiedSignature() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await EcdsaSign.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
    const verifier = await EcdsaVerify.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
    const data = Random.randBytes(20);
    const signature = await signer.sign(data);

    for (let i = 0; i < signature.length; i++) {
      for (let j = 0; j < 8; j++) {
        const s1 = new Uint8Array(signature);
        s1[i] = (s1[i] ^ (1 << j));
        assertFalse(await verifier.verify(s1, data));
      }
    }
  },

  async testVerifyModifiedData() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await EcdsaSign.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
    const verifier = await EcdsaVerify.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
    const data = Random.randBytes(20);
    const signature = await signer.sign(data);

    for (let i = 0; i < data.length; i++) {
      for (let j = 0; j < 8; j++) {
        const data1 = new Uint8Array(data);
        data1[i] = (data1[i] ^ (1 << j));
        assertFalse(await verifier.verify(signature, data1));
      }
    }
  },

  async testWycheproof() {
    for (let testGroup of wycheproofEcdsaTestVectors['testGroups']) {
      try {
        Validators.validateEcdsaParams(
            testGroup['jwk']['crv'], testGroup['sha']);
      } catch (e) {
        // Tink does not support this config.
        continue;
      }
      const verifier =
          await EcdsaVerify.newInstance(testGroup['jwk'], testGroup['sha']);
      let errors = '';
      for (let test of testGroup['tests']) {
        errors += await runWycheproofTest(verifier, test);
      }
      if (errors !== '') {
        fail(errors);
      }
    }
  },

});

/**
 * Runs the test with test vector given as an input and returns either empty
 * string or a text describing the failure.
 *
 * @param {!EcdsaVerify} verifier
 * @param {!Object} test - JSON object with test data
 * @return {!Promise<string>}
 */
const runWycheproofTest = async function(verifier, test) {
  try {
    const sig = Bytes.fromHex(test['sig']);
    const msg = Bytes.fromHex(test['msg']);
    const isValid = await verifier.verify(sig, msg);
    if (isValid) {
      if (test['result'] === 'invalid') {
        return 'invalid signature accepted on test ' + test['tcId'] + '\n';
      }
    } else {
      if (test['result'] === 'valid') {
        return 'valid signature rejected on test ' + test['tcId'] + '\n';
      }
    }
  } catch (e) {
    if (test['result'] === 'valid') {
      return 'valid signature rejected on test ' + test['tcId'] +
          ': unexpected exception \"' + e.toString() + '\".\n';
    }
  }
  // If the test passes return an empty string.
  return '';
};
