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

goog.module('tink.subtle.EcdsaSignTest');
goog.setTestOnly('tink.subtle.EcdsaSignTest');

const EcdsaSign = goog.require('tink.subtle.EcdsaSign');
const EllipticCurves = goog.require('tink.subtle.EllipticCurves');
const Environment = goog.require('tink.subtle.Environment');
const Random = goog.require('tink.subtle.Random');
const TestCase = goog.require('goog.testing.TestCase');
const testSuite = goog.require('goog.testing.testSuite');
const userAgent = goog.require('goog.userAgent');

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

  async testSign() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await EcdsaSign.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
    for (let i = 0; i < 100; i++) {
      const data = Random.randBytes(i);
      const signature = await signer.sign(data);
      const isValid = await window.crypto.subtle.verify(
          {
            name: 'ECDSA',
            hash: {
              name: 'SHA-256',
            },
          },
          keyPair.publicKey, signature, data);
      assertTrue(isValid);
    }
  },

  async testSignWithDerEncoding() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await EcdsaSign.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256',
        EllipticCurves.EcdsaSignatureEncodingType.DER);
    for (let i = 0; i < 100; i++) {
      const data = Random.randBytes(i);
      let signature = await signer.sign(data);
      // Should fail WebCrypto only accepts IEEE encoding.
      let isValid = await window.crypto.subtle.verify(
          {
            name: 'ECDSA',
            hash: {
              name: 'SHA-256',
            },
          },
          keyPair.publicKey, signature, data);
      assertFalse(isValid);
      // Convert the signature to IEEE encoding.
      signature = EllipticCurves.ecdsaDer2Ieee(signature, 64);
      isValid = await window.crypto.subtle.verify(
          {
            name: 'ECDSA',
            hash: {
              name: 'SHA-256',
            },
          },
          keyPair.publicKey, signature, data);
      assertTrue(isValid);
    }
  },

  async testSignAlwaysGenerateNewSignatures() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await EcdsaSign.newInstance(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
    const signatures = new Set();
    for (let i = 0; i < 100; i++) {
      const data = Random.randBytes(i);
      const signature = await signer.sign(data);
      signatures.add(signature);
    }
    assertEquals(100, signatures.size);
  },

  async testConstructorWithNullPrivateKey() {
    try {
      await EcdsaSign.newInstance(null, 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: private key has to be non-null', e.toString());
    }
  },

  async testConstructorWithInvalidHash() {
    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
      await EcdsaSign.newInstance(
          await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-1');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-256 (because curve is P-256) but ' +
              'got SHA-1',
          e.toString());
    }

    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-384');
      await EcdsaSign.newInstance(
          await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals(
          'CustomError: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256',
          e.toString());
    }

    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-521');
      await EcdsaSign.newInstance(
          await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
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
      const jwk = await EllipticCurves.exportCryptoKey(keyPair.privateKey);
      jwk.crv = 'blah';
      await EcdsaSign.newInstance(jwk, 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      assertEquals('CustomError: unsupported curve: blah', e.toString());
    }
  },
});
