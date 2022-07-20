/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {AeadConfig} from '../aead/aead_config';
import {AeadKeyTemplates} from '../aead/aead_key_templates';
import {RegistryEciesAeadHkdfDemHelper} from '../hybrid/registry_ecies_aead_hkdf_dem_helper';
import * as Registry from '../internal/registry';

import {fromJsonWebKey} from './ecies_aead_hkdf_hybrid_encrypt';
import * as EllipticCurves from './elliptic_curves';
import * as Random from './random';

describe('ecies aead hkdf hybrid encrypt test', function() {
  beforeEach(function() {
    AeadConfig.register();
    // Use a generous promise timeout for running continuously.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000 * 1000;  // 1000s
  });

  afterEach(function() {
    Registry.reset();
    // Reset the timeout.
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;  // 1s
  });

  it('new instance, should work', async function() {
    const keyPair = await EllipticCurves.generateKeyPair('ECDH', 'P-256');
    const publicKey = await EllipticCurves.exportCryptoKey(keyPair.publicKey!);
    const hkdfHash = 'SHA-256';
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new RegistryEciesAeadHkdfDemHelper(
        AeadKeyTemplates.aes128CtrHmacSha256());

    await fromJsonWebKey(publicKey, hkdfHash, pointFormat, demHelper);
  });

  it('encrypt, different arguments', async function() {
    const hkdfSalt = new Uint8Array(0);
    const pointFormat = EllipticCurves.PointFormatType.UNCOMPRESSED;
    const demHelper = new RegistryEciesAeadHkdfDemHelper(
        AeadKeyTemplates.aes256CtrHmacSha256());
    const hmacAlgorithms = ['SHA-1', 'SHA-256', 'SHA-512'];

    // Test the encryption for different HMAC algorithms and different types of
    // curves.
    for (const hkdfHash of hmacAlgorithms) {
      for (const curve
               of [EllipticCurves.CurveType.P256, EllipticCurves.CurveType.P384,
                   EllipticCurves.CurveType.P521]) {
        const curveName = EllipticCurves.curveToString(curve);
        const keyPair =
            await EllipticCurves.generateKeyPair('ECDH', curveName!);
        const publicKey =
            await EllipticCurves.exportCryptoKey(keyPair.publicKey!);

        const hybridEncrypt = await fromJsonWebKey(
            publicKey, hkdfHash, pointFormat, demHelper, hkdfSalt);

        const plaintext = Random.randBytes(15);
        const ciphertext = await hybridEncrypt.encrypt(plaintext);

        expect(ciphertext).not.toEqual(plaintext);
      }
    }
  });
});
