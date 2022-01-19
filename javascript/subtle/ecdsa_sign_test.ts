/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {fromJsonWebKey} from './ecdsa_sign';
import * as EllipticCurves from './elliptic_curves';
import * as Random from './random';

describe('ecdsa sign test', function() {
  beforeEach(function() {
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('sign', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!), 'SHA-256');
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
          keyPair.publicKey!, signature, data);
      expect(isValid).toBe(true);
    }
  });

  it('sign with der encoding', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!), 'SHA-256',
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
          keyPair.publicKey!, signature, data);
      expect(isValid).toBe(false);
      // Convert the signature to IEEE encoding.
      signature = EllipticCurves.ecdsaDer2Ieee(signature, 64);
      isValid = await window.crypto.subtle.verify(
          {
            name: 'ECDSA',
            hash: {
              name: 'SHA-256',
            },
          },
          keyPair.publicKey!, signature, data);
      expect(isValid).toBe(true);
    }
  });

  it('sign always generate new signatures', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
    const signer = await fromJsonWebKey(
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!), 'SHA-256');
    const signatures = new Set();
    for (let i = 0; i < 100; i++) {
      const data = Random.randBytes(i);
      const signature = await signer.sign(data);
      signatures.add(signature);
    }
    expect(signatures.size).toBe(100);
  });

  it('constructor with invalid hash', async function() {
    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
      await fromJsonWebKey(
          await EllipticCurves.exportCryptoKey(keyPair.privateKey!), 'SHA-1');
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-256 (because curve is P-256) but ' +
              'got SHA-1');
    }

    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-384');
      await fromJsonWebKey(
          await EllipticCurves.exportCryptoKey(keyPair.privateKey!), 'SHA-256');
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-384 or SHA-512 (because curve is P-384) but got SHA-256');
    }

    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-521');
      await fromJsonWebKey(
          await EllipticCurves.exportCryptoKey(keyPair.privateKey!), 'SHA-256');
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString())
          .toBe(
              'SecurityException: expected SHA-512 (because curve is P-521) but got SHA-256');
    }
  });

  it('constructor with invalid curve', async function() {
    try {
      const keyPair = await EllipticCurves.generateKeyPair('ECDSA', 'P-256');
      const jwk = await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
      jwk.crv = 'blah';
      await fromJsonWebKey(jwk, 'SHA-256');
      fail('Should throw an exception.');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString()).toBe('SecurityException: unsupported curve: blah');
    }
  });
});
