/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../aead/aead_config';
import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {RegistryEciesAeadHkdfDemHelper as DemHelper} from '../hybrid/registry_ecies_aead_hkdf_dem_helper';
import * as Registry from '../internal/registry';

import {fromJsonWebKey as decrypterFromJsonWebKey} from './ecies_aead_hkdf_hybrid_decrypt';
import {fromJsonWebKey as encrypterFromJsonWebKey} from './ecies_aead_hkdf_hybrid_encrypt';
import * as EllipticCurves from './elliptic_curves';
import * as Random from './random';

describe('ecies aead hkdf hybrid decrypt test', function() {
  beforeEach(function() {
    AeadConfig.register();
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    Registry.reset();
    // Reset the promise timeout to default value.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('new instance, should work', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const privateKey =
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
    const hkdfSalt = new Uint8Array(0);
    const hkdfHash = 'SHA-256';
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new DemHelper(AeadKeyTemplates.aes128CtrHmacSha256());

    await decrypterFromJsonWebKey(
        privateKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
  });

  it('decrypt, short ciphertext, should not work', async function() {
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new DemHelper(AeadKeyTemplates.aes128CtrHmacSha256());
    const hkdfHash = 'SHA-512';
    const curve = EllipticCurves.CurveType.P256;

    const curveName = EllipticCurves.curveToString(curve);
    const curveEncodingSize =
        EllipticCurves.encodingSizeInBytes(curve, pointFormat);

    const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
    const privateKey =
        await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);

    const hybridEncrypt = await encrypterFromJsonWebKey(
        publicKey, hkdfHash, pointFormat, demHelper);
    const hybridDecrypt = await decrypterFromJsonWebKey(
        privateKey, hkdfHash, pointFormat, demHelper);

    const plaintext = Random.randBytes(10);
    const ciphertext = await hybridEncrypt.encrypt(plaintext);
    try {
      await hybridDecrypt.decrypt(ciphertext.slice(0, curveEncodingSize - 1));
      fail('Should throw an exception');
      // Preserving old behavior when moving to
      // https://www.typescriptlang.org/tsconfig#useUnknownInCatchVariables
      // tslint:disable-next-line:no-any
    } catch (e: any) {
      expect(e.toString()).toBe('SecurityException: Ciphertext is too short.');
    }
  });

  it('decrypt, different dem helpers from one template, should work',
     async function() {
       const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
       const privateKey =
           await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
       const publicKey =
           await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
       const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
       const hkdfHash = 'SHA-256';
       const keyTemplate = AeadKeyTemplates.aes256CtrHmacSha256();

       const demHelperEncrypt = new DemHelper(keyTemplate);
       const hybridEncrypt = await encrypterFromJsonWebKey(
           publicKey, hkdfHash, pointFormat, demHelperEncrypt);

       const demHelperDecrypt = new DemHelper(keyTemplate);
       const hybridDecrypt = await decrypterFromJsonWebKey(
           privateKey, hkdfHash, pointFormat, demHelperDecrypt);

       const plaintext = Random.randBytes(15);

       const ciphertext = await hybridEncrypt.encrypt(plaintext);
       const decryptedCipher = await hybridDecrypt.decrypt(ciphertext);
       expect(decryptedCipher).toEqual(plaintext);
     });

  it('decrypt, different pamarameters, should work', async function() {
    const repetitions = 5;
    const hkdfSalt = new Uint8Array(0);

    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const hmacAlgorithms = ['SHA-1', 'SHA-256', 'SHA-512'];
    const demHelper = new DemHelper(AeadKeyTemplates.aes256CtrHmacSha256());
    const curves = [
      EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
      EllipticCurves.CurveType.P521
    ];

    // Test the encryption for different HMAC algorithms and different types of
    // curves.
    for (const hkdfHash of hmacAlgorithms) {
      for (const curve of curves) {
        const curveName = EllipticCurves.curveToString(curve);
        const keyPair = await EllipticCurves.generateKeyPair('ECDH', curveName);
        const privateKey =
            await EllipticCurves.exportCryptoKey(keyPair.privateKey!);
        const publicKey =
            await EllipticCurves.exportCryptoKey(keyPair.publicKey!);

        const hybridEncrypt = await encrypterFromJsonWebKey(
            publicKey, hkdfHash, pointFormat, demHelper, hkdfSalt);
        const hybridDecrypt = await decrypterFromJsonWebKey(
            privateKey, hkdfHash, pointFormat, demHelper, hkdfSalt);

        for (let i = 0; i < repetitions; ++i) {
          const plaintext = Random.randBytes(15);
          const contextInfo = Random.randBytes(i);
          const ciphertext =
              await hybridEncrypt.encrypt(plaintext, contextInfo);
          const decryptedCiphertext =
              await hybridDecrypt.decrypt(ciphertext, contextInfo);

          expect(decryptedCiphertext).toEqual(plaintext);
        }
      }
    }
  });
});
