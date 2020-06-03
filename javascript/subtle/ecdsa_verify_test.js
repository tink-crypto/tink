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

const Bytes = goog.require('google3.third_party.tink.javascript.subtle.bytes');
const EllipticCurves = goog.require('google3.third_party.tink.javascript.subtle.elliptic_curves');
const Random = goog.require('google3.third_party.tink.javascript.subtle.random');
const Validators = goog.require('google3.third_party.tink.javascript.subtle.validators');
const wycheproofEcdsaTestVectors = goog.require('tink.subtle.wycheproofEcdsaTestVectors');
const ecdsaSign = goog.require('google3.third_party.tink.javascript.subtle.ecdsa_sign');
const ecdsaVerify = goog.require('google3.third_party.tink.javascript.subtle.ecdsa_verify');
const {PublicKeyVerify} = goog.require('google3.third_party.tink.javascript.signature.internal.public_key_verify');

describe('ecdsa verify test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('verify', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await ecdsaSign.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
    const verifier = await ecdsaVerify.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
    for (let i = 0; i < 100; i++) {
      const data = Random.randBytes(i);
      const signature = await signer.sign(data);
      expect(await verifier.verify(signature, data)).toBe(true);
    }
  });

  it('verify with der encoding', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await ecdsaSign.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256',
        EllipticCurves.EcdsaSignatureEncodingType.DER);
    const verifier = await ecdsaVerify.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
    const verifierDer = await ecdsaVerify.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256',
        EllipticCurves.EcdsaSignatureEncodingType.DER);
    for (let i = 0; i < 100; i++) {
      const data = Random.randBytes(i);
      const signature = await signer.sign(data);
      expect(await verifier.verify(signature, data)).toBe(false);
      expect(await verifierDer.verify(signature, data)).toBe(true);
    }
  });

  it('constructor with invalid hash', async function() {
    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
      await ecdsaVerify.fromJsonWebKey(
          await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-1');
      fail('Should throw an exception.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-256 (because curve is P-256) but got SHA-1');
    }

    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-384');
      await ecdsaVerify.fromJsonWebKey(
          await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256');
    }

    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-521');
      await ecdsaVerify.fromJsonWebKey(
          await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-512 (because curve is P-521) but got SHA-256');
    }
  });

  it('constructor with invalid curve', async function() {
    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
      const jwk = await EllipticCurves.exportCryptoKey(keyPair.publicKey);
      jwk.crv = 'blah';
      await ecdsaVerify.fromJsonWebKey(jwk, 'SHA-256');
      fail('Should throw an exception.');
    } catch (e) {
      expect(e.toString()).toBe('SecurityException: unsupported curve: blah');
    }
  });

  it('verify modified signature', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await ecdsaSign.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
    const verifier = await ecdsaVerify.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
    const data = Random.randBytes(20);
    const signature = await signer.sign(data);

    for (let i = 0; i < signature.length; i++) {
      for (let j = 0; j < 8; j++) {
        const s1 = new Uint8Array(signature);
        s1[i] = (s1[i] ^ (1 << j));
        expect(await verifier.verify(s1, data)).toBe(false);
      }
    }
  });

  it('verify modified data', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await ecdsaSign.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey), 'SHA-256');
    const verifier = await ecdsaVerify.fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.publicKey), 'SHA-256');
    const data = Random.randBytes(20);
    const signature = await signer.sign(data);

    for (let i = 0; i < data.length; i++) {
      for (let j = 0; j < 8; j++) {
        const data1 = new Uint8Array(data);
        data1[i] = (data1[i] ^ (1 << j));
        expect(await verifier.verify(signature, data1)).toBe(false);
      }
    }
  });

  it('wycheproof', async function() {
    for (let testGroup of wycheproofEcdsaTestVectors['testGroups']) {
      try {
        Validators.validateEcdsaParams(
            testGroup['jwk']['crv'], testGroup['sha']);
      } catch (e) {
        // Tink does not support this config.
        continue;
      }
      const verifier =
          await ecdsaVerify.fromJsonWebKey(testGroup['jwk'], testGroup['sha']);
      let errors = '';
      for (let test of testGroup['tests']) {
        errors += await runWycheproofTest(verifier, test);
      }
      if (errors !== '') {
        fail(errors);
      }
    }
  });
});

/**
 * Runs the test with test vector given as an input and returns either empty
 * string or a text describing the failure.
 *
 * @param {!PublicKeyVerify} verifier
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
