/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Bytes from './bytes';
import {EciesHkdfKemSender, fromJsonWebKey} from './ecies_hkdf_kem_sender';
import * as EllipticCurves from './elliptic_curves';
import * as Random from './random';

describe('ecies hkdf kem sender test', function() {
  it('encapsulate, always generate random key', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
    const sender = await fromJsonWebKey(publicKey);
    const keySizeInBytes = 32;
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const hkdfHash = 'SHA-256';
    const hkdfInfo = Random.randBytes(32);
    const hkdfSalt = Random.randBytes(32);
    const keys = new Set();
    const tokens = new Set();
    for (let i = 0; i < 20; i++) {
      const kemKeyToken = await sender.encapsulate(
          keySizeInBytes, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);
      keys.add(Bytes.toHex(kemKeyToken['key']));
      tokens.add(Bytes.toHex(kemKeyToken['token']));
    }
    expect(keys.size).toBe(20);
    expect(tokens.size).toBe(20);
  });

  it('encapsulate, non integer key size', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
    const sender = await fromJsonWebKey(publicKey);
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const hkdfHash = 'SHA-256';
    const hkdfInfo = Random.randBytes(32);
    const hkdfSalt = Random.randBytes(32);
    try {
      await sender.encapsulate(NaN, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: size must be an integer');
    }
    try {
      await sender.encapsulate(0, pointFormat, hkdfHash, hkdfInfo, hkdfSalt);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe('InvalidArgumentsException: size must be positive');
    }
  });

  it('new instance, invalid parameters', async function() {
    // Test fromJsonWebKey with public key instead private key.
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const privateKey =
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
    try {
      await fromJsonWebKey(privateKey);
      fail('An exception should be thrown.');
    } catch (e) {
    }
  });

  it('new instance, invalid public key', async function() {
    for (const curve
             of [EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
                 EllipticCurves.CurveType.P521]) {
      const crvString = EllipticCurves.curveToString(curve);
      const keyPair = await EllipticCurves.generateKeyPair('ECDH', crvString);
      const publicJwk =
          await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
      // Change the 'x' value to make the public key invalid. Either getting new
      // recipient with corrupted public key or trying to encapsulate with this
      // recipient should fail.
      const xLength = EllipticCurves.fieldSizeInBytes(curve);
      publicJwk['x'] =
          Bytes.toBase64(new Uint8Array(xLength), /* opt_webSafe = */ true);
      const hkdfInfo = Random.randBytes(10);
      const salt = Random.randBytes(8);
      try {
        const sender = await fromJsonWebKey(publicJwk);
        await sender.encapsulate(
            /* keySizeInBytes = */ 32,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            /* hkdfHash = */ 'SHA-256', hkdfInfo, salt);
        fail('Should throw an exception.');
      } catch (e) {
      }
    }
  });

  it('constructor, invalid parameters', async function() {
    // Test constructor with public key instead private key.
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    try {
      new EciesHkdfKemSender(keyPair.privateKey!);
      fail('An exception should be thrown.');
    } catch (e) {
      expect(e.toString())
          .toBe('SecurityException: Expected Crypto key of type: public.');
    }
  });
});
