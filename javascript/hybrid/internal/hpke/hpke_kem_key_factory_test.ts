/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {SecurityException} from '../../../exception/security_exception';
import {PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeParams, PbHpkePrivateKey, PbHpkePublicKey} from '../../../internal/proto';
import * as bytes from '../../../subtle/bytes';

import {HpkeKemKeyFactory} from './hpke_kem_key_factory';

interface TestVector {
  kem: PbHpkeKem;
  kdf: PbHpkeKdf;
  aead: PbHpkeAead;
  senderPublicKey: Uint8Array;
  senderPrivateKey: Uint8Array;
}

const VERSION = 0;

/**
 * Test vectors as described in @see https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
 */
const TEST_VECTORS: TestVector[] = [
  /** Test vector for DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM */
  {
    kem: PbHpkeKem.DHKEM_P256_HKDF_SHA256,
    kdf: PbHpkeKdf.HKDF_SHA256,
    aead: PbHpkeAead.AES_128_GCM,
    senderPublicKey: bytes.fromHex(
        '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'),
    senderPrivateKey: bytes.fromHex(
        '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb'),
  },
  /** Test vector for DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM */
  {
    kem: PbHpkeKem.DHKEM_P521_HKDF_SHA512,
    kdf: PbHpkeKdf.HKDF_SHA512,
    aead: PbHpkeAead.AES_256_GCM,
    senderPublicKey: bytes.fromHex(
        '040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0'),
    senderPrivateKey: bytes.fromHex(
        '014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b'),
  }
];

function createHpkePrivateKey(
    kem: PbHpkeKem, kdf: PbHpkeKdf, aead: PbHpkeAead,
    publicKeyBytes: Uint8Array, privateKeyBytes: Uint8Array): PbHpkePrivateKey {
  const hpkeParams = new PbHpkeParams().setKem(kem).setKdf(kdf).setAead(aead);
  const hpkePublicKey = new PbHpkePublicKey()
                            .setParams(hpkeParams)
                            .setPublicKey(publicKeyBytes)
                            .setVersion(VERSION);

  return new PbHpkePrivateKey()
      .setPrivateKey(privateKeyBytes)
      .setPublicKey(hpkePublicKey)
      .setVersion(VERSION);
}

describe('HpkeKemKeyFactory', () => {
  for (const testInfo of TEST_VECTORS) {
    const hpkePrivateKey = createHpkePrivateKey(
        testInfo.kem, testInfo.kdf, testInfo.aead, testInfo.senderPublicKey,
        testInfo.senderPrivateKey);
    it('should create kem private key from valid hpke private key',
       async () => {
         const kemPrivateKey =
             await HpkeKemKeyFactory.createPrivate(hpkePrivateKey);
         expect(await kemPrivateKey.getSerializedPublicKey())
             .toEqual(testInfo.senderPublicKey);
       });
    describe('fails to create kem private key from invalid', () => {
      it('public key', async () => {
        const invalidHpkePrivateKey = createHpkePrivateKey(
            testInfo.kem, testInfo.kdf, testInfo.aead, new Uint8Array(0),
            testInfo.senderPrivateKey);
        try {
          await HpkeKemKeyFactory.createPrivate(invalidHpkePrivateKey);
          fail('An exception should be thrown.');
        } catch (e: unknown) {
          expect((e as SecurityException).message).toBe('invalid point');
        }
      });
      it('kem params', async () => {
        const invalidHpkePrivateKey = createHpkePrivateKey(
            PbHpkeKem.KEM_UNKNOWN, testInfo.kdf, testInfo.aead,
            testInfo.senderPublicKey, testInfo.senderPrivateKey);
        try {
          await HpkeKemKeyFactory.createPrivate(invalidHpkePrivateKey);
          fail('An exception should be thrown.');
        } catch (e: unknown) {
          expect((e as InvalidArgumentsException).message)
              .toBe('Unrecognized HPKE KEM identifier');
        }
      });
    });
  }
});
