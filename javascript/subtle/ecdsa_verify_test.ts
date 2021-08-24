/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PublicKeyVerify} from '../signature/internal/public_key_verify';

import * as Bytes from './bytes';
import * as ecdsaSign from './ecdsa_sign';
import * as ecdsaVerify from './ecdsa_verify';
import * as EllipticCurves from './elliptic_curves';
import * as Random from './random';
import * as Validators from './validators';
import {WYCHEPROOF_ECDSA_TEST_VECTORS} from './wycheproof_ecdsa_test_vectors';

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
    for (const testGroup of WYCHEPROOF_ECDSA_TEST_VECTORS['testGroups']) {
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
      for (const test of testGroup['tests']) {
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
 */
async function runWycheproofTest(
    verifier: PublicKeyVerify,
    test: {'tcId': number, 'msg': string, 'sig': string, 'result': string}):
    Promise<string> {
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
          ': unexpected exception "' + String(e) + '".\n';
    }
  }
  // If the test passes return an empty string.
  return '';
}
